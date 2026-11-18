package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

type rawConfig struct {
	Targets               []targetSpec `json:"targets"`
	Proxies               []proxySpec  `json:"proxies"`
	Rules                 []ruleSpec   `json:"rules"`
	DefaultProxy          string       `json:"default_proxy,omitempty"`
	TimeoutMS             int          `json:"timeout_ms,omitempty"`
	ConnectTimeoutMS      int          `json:"connect_timeout_ms,omitempty"`
	ReadTimeoutMS         int          `json:"read_timeout_ms,omitempty"`
	ProxyFailureThreshold int          `json:"proxy_failure_threshold,omitempty"`
	Summary               *bool        `json:"summary,omitempty"`
}

type targetSpec struct {
	Host string `json:"host"`
	Rule string `json:"rule,omitempty"`
}

func (t *targetSpec) UnmarshalJSON(data []byte) error {
	var host string
	if err := json.Unmarshal(data, &host); err == nil {
		t.Host = host
		return nil
	}

	type targetAlias targetSpec
	var value targetAlias
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&value); err != nil {
		return err
	}
	*t = targetSpec(value)
	return nil
}

type proxySpec struct {
	ID          string `json:"id,omitempty"`
	Address     string `json:"address"`
	UsernameEnv string `json:"username_env,omitempty"`
	PasswordEnv string `json:"password_env,omitempty"`
}

type ruleSpec struct {
	ID      string `json:"id,omitempty"`
	CIDR    string `json:"cidr"`
	ProxyID string `json:"proxy_id,omitempty"`
}

type runtimePlan struct {
	router    *router
	stats     *statsCollector
	targets   []target
	proxyMode bool
	summary   bool
}

type lookupEnvFunc func(string) (string, bool)

func buildPlan(opts options, lookupEnv lookupEnvFunc) (*runtimePlan, error) {
	timeout := time.Duration(opts.timeoutMS) * time.Millisecond
	connectTimeout := time.Duration(opts.connectTimeoutMS) * time.Millisecond
	readTimeout := time.Duration(opts.readTimeoutMS) * time.Millisecond
	failThreshold := opts.failThreshold
	summary := opts.summary
	summaryExplicit := opts.summarySet

	var cfg rawConfig
	if opts.configPath != "" {
		loaded, err := loadConfig(opts.configPath)
		if err != nil {
			return nil, err
		}
		cfg = loaded

		if cfg.TimeoutMS < 0 || cfg.ConnectTimeoutMS < 0 || cfg.ReadTimeoutMS < 0 || cfg.ProxyFailureThreshold < 0 {
			return nil, fmt.Errorf("config: timeouts and proxy_failure_threshold must not be negative")
		}
		if cfg.TimeoutMS != 0 {
			timeout = time.Duration(cfg.TimeoutMS) * time.Millisecond
		}
		if cfg.ConnectTimeoutMS != 0 {
			connectTimeout = time.Duration(cfg.ConnectTimeoutMS) * time.Millisecond
		}
		if cfg.ReadTimeoutMS != 0 {
			readTimeout = time.Duration(cfg.ReadTimeoutMS) * time.Millisecond
		}
		if cfg.ProxyFailureThreshold != 0 {
			failThreshold = cfg.ProxyFailureThreshold
		}
		if cfg.Summary != nil && !opts.summarySet {
			summary = *cfg.Summary
			summaryExplicit = true
		}
	}

	if opts.proxy != "" {
		cfg.Proxies = append(cfg.Proxies, proxySpec{
			ID:          "P0",
			Address:     opts.proxy,
			UsernameEnv: opts.proxyUserEnv,
			PasswordEnv: opts.proxyPasswordEnv,
		})
		cfg.DefaultProxy = "P0"
	}

	if connectTimeout == 0 {
		connectTimeout = timeout
	}
	if readTimeout == 0 {
		readTimeout = timeout
	}
	if failThreshold == 0 {
		failThreshold = 5
	}

	proxyIDs, rules, err := normalizeConfigNames(cfg)
	if err != nil {
		return nil, err
	}

	ruleUsage := make(map[string][]string)
	for i, rule := range cfg.Rules {
		proxyID := strings.TrimSpace(rule.ProxyID)
		if proxyID != "" && proxyID != "direct" {
			id := rule.ID
			if id == "" {
				id = rules[i]
			}
			ruleUsage[proxyID] = append(ruleUsage[proxyID], strings.TrimSpace(id))
		}
	}
	defaultProxyID := strings.TrimSpace(cfg.DefaultProxy)
	if defaultProxyID != "" {
		ruleUsage[defaultProxyID] = append(ruleUsage[defaultProxyID], "DEFAULT")
	}

	endpoints := make(map[string]*proxyEndpoint, len(cfg.Proxies))
	for i, spec := range cfg.Proxies {
		id := proxyIDs[i]
		usedBy := ruleUsage[id]

		endpoint, err := newProxyEndpoint(id, spec, lookupEnv, proxyTimeouts{
			overall: timeout,
			connect: connectTimeout,
			read:    readTimeout,
		}, failThreshold)
		if err != nil {
			if len(usedBy) > 0 {
				return nil, fmt.Errorf("config: proxy %s (rules %s): %w", id, strings.Join(usedBy, ","), err)
			}
			return nil, fmt.Errorf("config: proxy %s: %w", id, err)
		}
		endpoints[id] = endpoint
	}

	direct := newDirectRoute(proxyTimeouts{overall: timeout, connect: connectTimeout, read: readTimeout})
	compiledRules, err := compileRules(cfg.Rules, rules, endpoints, proxyTimeouts{
		overall: timeout,
		connect: connectTimeout,
		read:    readTimeout,
	})
	if err != nil {
		return nil, err
	}

	var defaultProxy *proxyEndpoint
	if defaultProxyID != "" {
		defaultProxy = endpoints[defaultProxyID]
		if defaultProxy == nil {
			return nil, fmt.Errorf("config: default_proxy %q does not match any proxy id", cfg.DefaultProxy)
		}
	}

	targets, err := compileTargets(cfg.Targets, rules)
	if err != nil {
		return nil, err
	}

	router := &router{
		rules:  compiledRules,
		byID:   make(map[string]*route, len(compiledRules)),
		direct: direct,
	}
	for _, rule := range compiledRules {
		router.byID[rule.ruleID] = rule
	}
	if defaultProxy != nil {
		router.defaultRoute = &route{
			ruleID: "DEFAULT",
			cidr:   "unmatched",
			proxy:  defaultProxy,
			client: defaultProxy.client,
		}
	}

	proxyMode := len(endpoints) > 0
	if proxyMode && !summaryExplicit {
		summary = true
	}

	return &runtimePlan{
		router:    router,
		stats:     newStatsCollector(),
		targets:   targets,
		proxyMode: proxyMode,
		summary:   summary,
	}, nil
}

func loadConfig(path string) (rawConfig, error) {
	var cfg rawConfig
	file, err := os.Open(path)
	if err != nil {
		return cfg, fmt.Errorf("open config %q: %w", path, err)
	}
	defer file.Close()

	dec := json.NewDecoder(file)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return cfg, fmt.Errorf("parse config %q: %w", path, err)
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		if err == nil {
			return cfg, fmt.Errorf("parse config %q: trailing JSON value", path)
		}
		return cfg, fmt.Errorf("parse config %q: %w", path, err)
	}

	return cfg, nil
}

func normalizeConfigNames(cfg rawConfig) ([]string, []string, error) {
	proxyIDs := make([]string, len(cfg.Proxies))
	seenProxies := make(map[string]struct{}, len(cfg.Proxies))
	for i, spec := range cfg.Proxies {
		id := strings.TrimSpace(spec.ID)
		if id == "" {
			id = "P" + strconv.Itoa(i)
		}
		if id == "direct" {
			return nil, nil, fmt.Errorf("config: proxy id %q is reserved", id)
		}
		if _, exists := seenProxies[id]; exists {
			return nil, nil, fmt.Errorf("config: duplicate proxy id %q", id)
		}
		seenProxies[id] = struct{}{}
		proxyIDs[i] = id
	}

	ruleIDs := make([]string, len(cfg.Rules))
	seenRules := make(map[string]struct{}, len(cfg.Rules))
	for i, spec := range cfg.Rules {
		id := strings.TrimSpace(spec.ID)
		if id == "" {
			id = "R" + strconv.Itoa(i)
		}
		if _, exists := seenRules[id]; exists {
			return nil, nil, fmt.Errorf("config: duplicate rule id %q", id)
		}
		seenRules[id] = struct{}{}
		ruleIDs[i] = id
	}

	return proxyIDs, ruleIDs, nil
}

func compileRules(specs []ruleSpec, ids []string, endpoints map[string]*proxyEndpoint, timeouts proxyTimeouts) ([]*route, error) {
	routes := make([]*route, 0, len(specs))
	for i, spec := range specs {
		id := ids[i]
		prefix, err := netip.ParsePrefix(strings.TrimSpace(spec.CIDR))
		if err != nil {
			return nil, fmt.Errorf("config: rule %s: invalid cidr %q: %w", id, spec.CIDR, err)
		}
		prefix = prefix.Masked()

		var proxy *proxyEndpoint
		proxyID := strings.TrimSpace(spec.ProxyID)
		if proxyID != "" && proxyID != "direct" {
			proxy = endpoints[proxyID]
			if proxy == nil {
				return nil, fmt.Errorf("config: rule %s: unknown proxy_id %q", id, proxyID)
			}
		}

		client := newDirectClient(timeouts)
		if proxy != nil {
			client = proxy.client
		}
		route := &route{
			ruleID: id,
			cidr:   prefix.String(),
			prefix: prefix,
			proxy:  proxy,
			client: client,
		}
		routes = append(routes, route)
	}

	sort.SliceStable(routes, func(i, j int) bool {
		return routes[i].prefix.Bits() > routes[j].prefix.Bits()
	})

	for i := 0; i < len(routes); i++ {
		for j := i + 1; j < len(routes); j++ {
			if routes[i].prefix.Bits() != routes[j].prefix.Bits() {
				continue
			}
			if routes[i].prefix.Overlaps(routes[j].prefix) {
				return nil, fmt.Errorf("config: rules %s and %s overlap with the same prefix length; use distinct prefix lengths", routes[i].ruleID, routes[j].ruleID)
			}
		}
	}

	return routes, nil
}

func compileTargets(specs []targetSpec, ruleNames []string) ([]target, error) {
	knownRules := make(map[string]struct{}, len(ruleNames))
	for _, id := range ruleNames {
		knownRules[id] = struct{}{}
	}

	targets := make([]target, 0, len(specs))
	for i, spec := range specs {
		host := strings.TrimSpace(strings.ToLower(spec.Host))
		if host == "" {
			return nil, fmt.Errorf("config: target %d has an empty host", i)
		}
		ruleID := strings.TrimSpace(spec.Rule)
		if ruleID != "" {
			if _, exists := knownRules[ruleID]; !exists {
				return nil, fmt.Errorf("config: target %q references unknown rule %q", host, ruleID)
			}
		}
		targets = append(targets, target{host: host, rule: ruleID})
	}
	return targets, nil
}

type proxyTimeouts struct {
	overall time.Duration
	connect time.Duration
	read    time.Duration
}

func validateProxyAddress(address string) (*url.URL, error) {
	parsed, err := url.Parse(strings.TrimSpace(address))
	if err != nil {
		return nil, fmt.Errorf("invalid address %q: %w", address, err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("invalid address %q: scheme must be http or https", address)
	}
	if parsed.User != nil {
		return nil, fmt.Errorf("invalid address %q: credentials must come from environment variables, not the proxy URL", address)
	}
	if parsed.Hostname() == "" {
		return nil, fmt.Errorf("invalid address %q: host is required", address)
	}
	if parsed.Port() == "" {
		return nil, fmt.Errorf("invalid address %q: port is required", address)
	}
	if _, err := strconv.Atoi(parsed.Port()); err != nil {
		return nil, fmt.Errorf("invalid address %q: port must be numeric", address)
	}
	port, _ := strconv.Atoi(parsed.Port())
	if port < 1 || port > 65535 {
		return nil, fmt.Errorf("invalid address %q: port must be between 1 and 65535", address)
	}
	if parsed.Path != "" && parsed.Path != "/" {
		return nil, fmt.Errorf("invalid address %q: path is not supported", address)
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, fmt.Errorf("invalid address %q: query and fragment are not supported", address)
	}
	return parsed, nil
}

func targetHost(hostport string) string {
	if host, _, err := net.SplitHostPort(hostport); err == nil {
		return strings.Trim(host, "[]")
	}
	return strings.Trim(hostport, "[]")
}
