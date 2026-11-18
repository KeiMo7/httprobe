package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"syscall"
	"time"
)

type proxyEndpoint struct {
	id      string
	client  *http.Client
	breaker *circuitBreaker
}

type route struct {
	ruleID string
	cidr   string
	prefix netip.Prefix
	proxy  *proxyEndpoint
	client *http.Client
}

type router struct {
	rules        []*route
	byID         map[string]*route
	direct       *route
	defaultRoute *route
}

func (r *router) routeFor(hostport, ruleOverride string) *route {
	if ruleOverride != "" {
		if selected := r.byID[ruleOverride]; selected != nil {
			return selected
		}
	}

	host := targetHost(hostport)
	if addr, err := netip.ParseAddr(host); err == nil {
		addr = addr.Unmap()
		for _, candidate := range r.rules {
			if candidate.prefix.Contains(addr) {
				return candidate
			}
		}
	}

	if r.defaultRoute != nil {
		return r.defaultRoute
	}
	return r.direct
}

func newProxyEndpoint(id string, spec proxySpec, lookupEnv lookupEnvFunc, timeouts proxyTimeouts, threshold int) (*proxyEndpoint, error) {
	address, err := validateProxyAddress(spec.Address)
	if err != nil {
		return nil, err
	}

	if (spec.UsernameEnv == "") != (spec.PasswordEnv == "") {
		return nil, fmt.Errorf("username_env and password_env must be configured together")
	}
	if spec.UsernameEnv != "" {
		username, ok := lookupEnv(spec.UsernameEnv)
		if !ok {
			return nil, fmt.Errorf("environment variable %s is not set", spec.UsernameEnv)
		}
		password, ok := lookupEnv(spec.PasswordEnv)
		if !ok {
			return nil, fmt.Errorf("environment variable %s is not set", spec.PasswordEnv)
		}
		address.User = url.UserPassword(username, password)
	}

	transport := newTransport(address, timeouts)
	client := &http.Client{
		Transport:     transport,
		CheckRedirect: stopRedirects,
		Timeout:       timeouts.overall,
	}

	return &proxyEndpoint{
		id:      id,
		client:  client,
		breaker: newCircuitBreaker(threshold),
	}, nil
}

func newDirectRoute(timeouts proxyTimeouts) *route {
	return &route{
		ruleID: "DIRECT",
		cidr:   "unmatched",
		client: newDirectClient(timeouts),
	}
}

func newDirectClient(timeouts proxyTimeouts) *http.Client {
	return &http.Client{
		Transport:     newTransport(nil, timeouts),
		CheckRedirect: stopRedirects,
		Timeout:       timeouts.overall,
	}
}

func newTransport(proxyURL *url.URL, timeouts proxyTimeouts) *http.Transport {
	transport := &http.Transport{
		MaxIdleConns:          30,
		IdleConnTimeout:       time.Second,
		DisableKeepAlives:     true,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
		ResponseHeaderTimeout: timeouts.read,
		DialContext: (&net.Dialer{
			Timeout:   timeouts.connect,
			KeepAlive: time.Second,
		}).DialContext,
	}
	if proxyURL != nil {
		transport.Proxy = http.ProxyURL(proxyURL)
	}
	return transport
}

func stopRedirects(req *http.Request, via []*http.Request) error {
	return http.ErrUseLastResponse
}

type circuitBreaker struct {
	mu        sync.Mutex
	threshold int
	failures  int
	open      bool
}

func newCircuitBreaker(threshold int) *circuitBreaker {
	return &circuitBreaker{threshold: threshold}
}

func (b *circuitBreaker) allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return !b.open
}

func (b *circuitBreaker) success() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.failures = 0
	b.open = false
}

func (b *circuitBreaker) failure() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.failures++
	if b.threshold > 0 && b.failures >= b.threshold {
		b.open = true
	}
}

func proxyLabel(route *route) string {
	if route.proxy == nil {
		return "direct"
	}
	return route.proxy.id
}

func formatSuccess(probeURL string, route *route, includeMetadata bool) string {
	if !includeMetadata {
		return probeURL
	}
	return fmt.Sprintf("%s\tproxy=%s\trule=%s", probeURL, proxyLabel(route), route.ruleID)
}

func formatFailure(probeURL string, route *route, result probeResult) string {
	return fmt.Sprintf(
		"FAIL\tcode=%s\ttarget=%s\tproxy=%s\trule=%s\tdetail=%q\n",
		result.code,
		probeURL,
		proxyLabel(route),
		route.ruleID,
		oneLine(result.detail),
	)
}

func oneLine(value string) string {
	value = strings.ReplaceAll(value, "\n", " ")
	value = strings.ReplaceAll(value, "\r", " ")
	return strings.TrimSpace(value)
}

func isDialTimeout(err error) bool {
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return opErr.Op == "dial" && isTimeout(opErr)
	}
	return false
}

func isTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func isConnectionRefused(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED)
}

func isDNSError(err error) bool {
	var dnsErr *net.DNSError
	return errors.As(err, &dnsErr)
}

func isTLSError(err error) bool {
	var recordErr tls.RecordHeaderError
	if errors.As(err, &recordErr) {
		return true
	}
	return strings.Contains(strings.ToLower(err.Error()), "tls:")
}
