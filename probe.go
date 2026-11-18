package main

import (
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
)

const (
	codeProxyConnectRefused  = "PROXY_CONNECT_REFUSED"
	codeProxyAuthRequired    = "PROXY_AUTH_REQUIRED"
	codeProxyBadGateway      = "PROXY_BAD_GATEWAY"
	codeProxyConnectTimeout  = "PROXY_CONNECT_TIMEOUT"
	codeProxyReadTimeout     = "PROXY_READ_TIMEOUT"
	codeProxyDNS             = "PROXY_DNS_ERROR"
	codeProxyTLS             = "PROXY_TLS_ERROR"
	codeProxyConnectError    = "PROXY_CONNECT_ERROR"
	codeProxyCircuitOpen     = "PROXY_CIRCUIT_OPEN"
	codeTargetInvalid        = "TARGET_INVALID"
	codeTargetConnectRefused = "TARGET_CONNECT_REFUSED"
	codeTargetTimeout        = "TARGET_TIMEOUT"
	codeTargetDNS            = "TARGET_DNS_ERROR"
	codeTargetTLS            = "TARGET_TLS_ERROR"
	codeTargetUnreachable    = "TARGET_UNREACHABLE"
)

type probeResult struct {
	ok           bool
	code         string
	detail       string
	proxyFailure bool
	circuitOpen  bool
}

func probeURL(route *route, probeURL, method string) probeResult {
	if route.proxy != nil && !route.proxy.breaker.allow() {
		return probeResult{
			code:         codeProxyCircuitOpen,
			detail:       "proxy circuit is open",
			proxyFailure: true,
			circuitOpen:  true,
		}
	}

	req, err := http.NewRequest(method, probeURL, nil)
	if err != nil {
		return probeResult{code: codeTargetInvalid, detail: err.Error()}
	}
	req.Header.Add("Connection", "close")
	req.Close = true

	resp, err := route.client.Do(req)
	if resp != nil {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()

		if route.proxy != nil {
			switch resp.StatusCode {
			case http.StatusProxyAuthRequired:
				route.proxy.breaker.failure()
				return probeResult{
					code:         codeProxyAuthRequired,
					detail:       resp.Status,
					proxyFailure: true,
				}
			case http.StatusBadGateway:
				route.proxy.breaker.failure()
				return probeResult{
					code:         codeProxyBadGateway,
					detail:       resp.Status,
					proxyFailure: true,
				}
			}
		}
	}

	if err != nil {
		result := classifyError(err, route)
		if route.proxy != nil {
			if result.proxyFailure {
				route.proxy.breaker.failure()
			} else {
				route.proxy.breaker.success()
			}
		}
		return result
	}

	if route.proxy != nil {
		route.proxy.breaker.success()
	}
	return probeResult{ok: true}
}

func classifyError(err error, route *route) probeResult {
	if route.proxy == nil {
		switch {
		case isDNSError(err):
			return probeResult{code: codeTargetDNS, detail: err.Error()}
		case isDialTimeout(err):
			return probeResult{code: codeTargetTimeout, detail: err.Error()}
		case isTimeout(err):
			return probeResult{code: codeTargetTimeout, detail: err.Error()}
		case isConnectionRefused(err):
			return probeResult{code: codeTargetConnectRefused, detail: err.Error()}
		case isTLSError(err):
			return probeResult{code: codeTargetTLS, detail: err.Error()}
		default:
			return probeResult{code: codeTargetUnreachable, detail: err.Error()}
		}
	}

	message := strings.ToLower(err.Error())
	switch {
	case strings.Contains(message, "proxy authentication required"):
		return probeResult{code: codeProxyAuthRequired, detail: err.Error(), proxyFailure: true}
	case strings.Contains(message, "bad gateway"):
		return probeResult{code: codeProxyBadGateway, detail: err.Error(), proxyFailure: true}
	case isDialTimeout(err):
		return probeResult{code: codeProxyConnectTimeout, detail: err.Error(), proxyFailure: true}
	case isTimeout(err):
		return probeResult{code: codeProxyReadTimeout, detail: err.Error(), proxyFailure: true}
	case isConnectionRefused(err):
		return probeResult{code: codeProxyConnectRefused, detail: err.Error(), proxyFailure: true}
	case isDNSError(err):
		return probeResult{code: codeProxyDNS, detail: err.Error(), proxyFailure: true}
	case isTLSError(err):
		return probeResult{code: codeProxyTLS, detail: err.Error(), proxyFailure: true}
	default:
		return probeResult{code: codeProxyConnectError, detail: err.Error(), proxyFailure: true}
	}
}

type statsKey struct {
	rule  string
	cidr  string
	proxy string
}

type statCount struct {
	checks      int
	ok          int
	targetFail  int
	proxyFail   int
	circuitOpen int
}

type statsCollector struct {
	mu     sync.Mutex
	values map[statsKey]*statCount
}

func newStatsCollector() *statsCollector {
	return &statsCollector{values: make(map[statsKey]*statCount)}
}

func (s *statsCollector) record(route *route, result probeResult) {
	key := statsKey{rule: route.ruleID, cidr: route.cidr, proxy: proxyLabel(route)}

	s.mu.Lock()
	defer s.mu.Unlock()

	count := s.values[key]
	if count == nil {
		count = &statCount{}
		s.values[key] = count
	}
	count.checks++
	switch {
	case result.ok:
		count.ok++
	case result.circuitOpen:
		count.circuitOpen++
	case result.proxyFailure:
		count.proxyFail++
	default:
		count.targetFail++
	}
}

func (s *statsCollector) print(w io.Writer) {
	s.mu.Lock()
	keys := make([]statsKey, 0, len(s.values))
	for key := range s.values {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].rule != keys[j].rule {
			return keys[i].rule < keys[j].rule
		}
		if keys[i].cidr != keys[j].cidr {
			return keys[i].cidr < keys[j].cidr
		}
		return keys[i].proxy < keys[j].proxy
	})
	counts := make([]statCount, len(keys))
	for i, key := range keys {
		counts[i] = *s.values[key]
	}
	s.mu.Unlock()

	for i, key := range keys {
		count := counts[i]
		io.WriteString(w, "SUMMARY")
		io.WriteString(w, "\trule="+key.rule)
		io.WriteString(w, "\tcidr="+key.cidr)
		io.WriteString(w, "\tproxy="+key.proxy)
		io.WriteString(w, "\tchecks="+itoa(count.checks))
		io.WriteString(w, "\tok="+itoa(count.ok))
		io.WriteString(w, "\ttarget_fail="+itoa(count.targetFail))
		io.WriteString(w, "\tproxy_fail="+itoa(count.proxyFail))
		io.WriteString(w, "\tcircuit_open="+itoa(count.circuitOpen))
		io.WriteString(w, "\n")
	}
}

func itoa(value int) string {
	const digits = "0123456789"
	if value == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for value > 0 {
		i--
		buf[i] = digits[value%10]
		value /= 10
	}
	return string(buf[i:])
}
