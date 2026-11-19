package main

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// status is the terminal state of one scheduled probe. Every target that
// enters the scheduler ends in exactly one of these states; there is no
// "unknown" hole.
type status string

const (
	// statusReachable means a TCP connection was established and an HTTP
	// response (of any status code) was received.
	statusReachable status = "reachable"
	// statusRefused means the remote host actively refused the connection
	// (ECONNREFUSED).
	statusRefused status = "refused"
	// statusTimeout means the dial or the HTTP exchange hit the configured
	// deadline.
	statusTimeout status = "timeout"
	// statusError covers any other terminal failure (DNS failure, TLS
	// handshake error, malformed input...). It is still terminal: the probe
	// was attempted.
	statusError status = "error"
	// statusCanceled means the probe was cut short by batch cancellation.
	statusCanceled status = "canceled"
	// statusSkipped means the target was deliberately not requested because
	// --prefer-https already found a working HTTPS endpoint. It is explicit,
	// not an accidental omission.
	statusSkipped status = "skipped"
)

// ErrorClass is the last connection-level error category seen for a probe.
// It is deliberately coarse so output stays stable and comparable between
// runs.
type ErrorClass string

const (
	errClassNone     ErrorClass = ""
	errClassRefused  ErrorClass = "connection_refused"
	errClassTimeout  ErrorClass = "timeout"
	errClassDNS      ErrorClass = "dns"
	errClassCanceled ErrorClass = "canceled"
	errClassTLS      ErrorClass = "tls"
	errClassInput    ErrorClass = "invalid_input"
	errClassPanic    ErrorClass = "panic"
	errClassUnknown  ErrorClass = "unknown"
)

// probeTarget is one (scheme, host:port) that must be attempted.
type probeTarget struct {
	Index  int
	Scheme string
	Host   string
	Port   string
	URL    string
}

// probeResult is the terminal result of probing one target.
type probeResult struct {
	Target    probeTarget
	Status    status
	Attempts  int
	LastError ErrorClass
	Error     string
}

func (r probeResult) Reachable() bool { return r.Status == statusReachable }

// probeGroup is a host:port plus the schemes that should be tried for it.
// HTTPS is tried first, then HTTP, matching the original tool's per-target
// flow. Targets carry a single global index, which is also the output order;
// that is what makes repeated runs directly comparable.
type probeGroup struct {
	HostPort   string
	HTTPSIndex int // -1 when this group has no HTTPS target
	HTTPIndex  int // -1 when this group has no HTTP target
}

type probePlan struct {
	Groups  []*probeGroup
	Targets []probeTarget
}

// classifyProbeError maps a concrete connection error to a status and error
// class. Classification is based on error types and syscall errnos, never on
// elapsed wall-clock time.
func classifyProbeError(err error) (status, ErrorClass) {
	if err == nil {
		return statusReachable, errClassNone
	}
	if errors.Is(err, context.Canceled) {
		return statusCanceled, errClassCanceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return statusTimeout, errClassTimeout
	}

	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return statusTimeout, errClassTimeout
	}

	// ECONNREFUSED is the canonical "nothing listening" signal.
	if errors.Is(err, syscall.ECONNREFUSED) {
		return statusRefused, errClassRefused
	}

	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		if dnsErr.IsTimeout {
			return statusTimeout, errClassTimeout
		}
		return statusError, errClassDNS
	}

	// Plaintext sent to a TLS listener is the most common non-timeout,
	// non-refused failure and has a concrete error type.
	var recordErr tls.RecordHeaderError
	if errors.As(err, &recordErr) {
		return statusError, errClassTLS
	}

	return statusError, errClassUnknown
}

// sanitiseError returns a stable, host-free error message. Target addresses
// and other input must never reach logs in raw form.
func sanitiseError(err error) string {
	if err == nil {
		return ""
	}
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline exceeded"
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "connection refused"
	case errors.Is(err, syscall.ECONNRESET):
		return "connection reset"
	case errors.Is(err, syscall.EHOSTUNREACH):
		return "host unreachable"
	case errors.Is(err, syscall.ENETUNREACH):
		return "network unreachable"
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "i/o timeout"
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return "dns lookup failed"
	}
	var recordErr tls.RecordHeaderError
	if errors.As(err, &recordErr) {
		return "tls handshake failed"
	}
	var urlErr *url.Error
	if errors.As(err, &urlErr) && urlErr.Err != nil && urlErr.Err != err {
		return sanitiseError(urlErr.Err)
	}
	return "request failed"
}

// prober performs probes with a bounded worker pool and explicit slots.
type prober struct {
	Client      *http.Client
	Method      string
	Timeout     time.Duration
	Attempts    int // attempts per target; >= 1
	RetryDelay  time.Duration
	Concurrency int
	PreferHTTPS bool
	Slots       *limiter

	// OnResult is called once per target as its terminal result is recorded.
	// It may be called concurrently from workers.
	OnResult func(probeResult)
	// OnProgress is called once per target with cumulative counts. It may be
	// called concurrently from workers.
	OnProgress func(done, total int)
}

func newProber(client *http.Client, method string, timeout time.Duration, concurrency, attempts int) *prober {
	if concurrency < 1 {
		concurrency = 1
	}
	if attempts < 1 {
		attempts = 1
	}
	return &prober{
		Client:      client,
		Method:      method,
		Timeout:     timeout,
		Attempts:    attempts,
		RetryDelay:  50 * time.Millisecond,
		Concurrency: concurrency,
		Slots:       newLimiter(concurrency),
	}
}

// Probe runs every group to completion and returns per-target results in
// target order. The order is independent of worker scheduling.
func (p *prober) Probe(ctx context.Context, plan *probePlan) []probeResult {
	results := make([]probeResult, len(plan.Targets))
	for i, t := range plan.Targets {
		// Seed every target with a terminal state before any work starts. If
		// a worker panics or a slot is leaked, the target still has a defined
		// result instead of being a silent hole.
		results[i] = probeResult{
			Target:    t,
			Status:    statusCanceled,
			Attempts:  0,
			LastError: errClassCanceled,
			Error:     "not attempted",
		}
	}
	if len(plan.Groups) == 0 {
		return results
	}

	if p.Slots == nil {
		p.Slots = newLimiter(p.Concurrency)
	}

	total := len(plan.Targets)
	var done int64
	jobs := make(chan *probeGroup)

	workers := p.Concurrency
	if workers < 1 {
		workers = 1
	}
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			for g := range jobs {
				p.runGroup(ctx, g, results, &done, total)
			}
		}()
	}

feed:
	for _, g := range plan.Groups {
		select {
		case jobs <- g:
		case <-ctx.Done():
			break feed
		}
	}
	close(jobs)
	wg.Wait()

	// Any target never dispatched is still given an explicit terminal state.
	// Committing a terminal result always records attempts >= 1, so attempts
	// == 0 is an unambiguous "never attempted" marker. (statusSkipped is set
	// with attempts 0 too, so it is handled explicitly.)
	for i := range results {
		if results[i].Attempts != 0 {
			continue
		}
		results[i].Status = statusCanceled
		results[i].LastError = errClassCanceled
		results[i].Error = "not attempted"
		if ctx.Err() == nil {
			results[i].Status = statusError
			results[i].LastError = errClassUnknown
			results[i].Error = "not attempted: scheduler did not dispatch target"
		}
	}
	return results
}

func (p *prober) runGroup(ctx context.Context, g *probeGroup, results []probeResult, done *int64, total int) {
	lease, err := p.Slots.Acquire(ctx)
	if err != nil {
		p.cancelUnfinished(g, results, done, total)
		return
	}
	// Release is paired with Acquire on every path, including panics.
	defer lease.Release()

	var httpsDone, httpDone bool
	defer func() {
		if r := recover(); r != nil {
			// Isolate a panic to this group; the rest of the batch continues
			// and every group member still gets a terminal state.
			if g.HTTPSIndex >= 0 && !httpsDone {
				p.commit(g.HTTPSIndex, panicResult(results[g.HTTPSIndex].Target), results, done, total)
			}
			if g.HTTPIndex >= 0 && !httpDone {
				p.commit(g.HTTPIndex, panicResult(results[g.HTTPIndex].Target), results, done, total)
			}
		}
	}()

	httpsReachable := false
	if g.HTTPSIndex >= 0 {
		res := p.probeTarget(ctx, results[g.HTTPSIndex].Target)
		p.commit(g.HTTPSIndex, res, results, done, total)
		httpsDone = true
		httpsReachable = res.Status == statusReachable
	}

	if g.HTTPIndex >= 0 {
		var res probeResult
		target := results[g.HTTPIndex].Target
		switch {
		case ctx.Err() != nil:
			res = terminalResult(target, statusCanceled, 0, errClassCanceled, "canceled before attempt")
		case p.PreferHTTPS && g.HTTPSIndex >= 0 && httpsReachable:
			// Preserve the original --prefer-https behaviour: HTTP is not
			// attempted when HTTPS already works. Attempts is 1 because the
			// target was considered, even though no request was sent.
			res = terminalResult(target, statusSkipped, 1, errClassNone, "")
		default:
			res = p.probeTarget(ctx, target)
		}
		p.commit(g.HTTPIndex, res, results, done, total)
		httpDone = true
	}
}

func (p *prober) cancelUnfinished(g *probeGroup, results []probeResult, done *int64, total int) {
	for _, idx := range []int{g.HTTPSIndex, g.HTTPIndex} {
		if idx < 0 {
			continue
		}
		p.commit(idx, terminalResult(results[idx].Target, statusCanceled, 0, errClassCanceled, "canceled before attempt"), results, done, total)
	}
}

// probeTarget tries one target up to p.Attempts times. A panic inside the
// probe is recovered here and isolated to this target.
func (p *prober) probeTarget(ctx context.Context, t probeTarget) (res probeResult) {
	res = terminalResult(t, statusError, 0, errClassUnknown, "not attempted")
	defer func() {
		if r := recover(); r != nil {
			res = panicResult(t)
		}
	}()

	attempts := p.Attempts
	if attempts < 1 {
		attempts = 1
	}
	for attempt := 1; attempt <= attempts; attempt++ {
		res.Attempts = attempt
		st, class, msg := p.tryOnce(ctx, t)
		res.Status = st
		res.LastError = class
		res.Error = msg

		if st == statusReachable || st == statusCanceled || st == statusSkipped {
			return res
		}
		if attempt < attempts && p.RetryDelay > 0 {
			timer := time.NewTimer(p.RetryDelay)
			select {
			case <-timer.C:
			case <-ctx.Done():
				timer.Stop()
				return terminalResult(t, statusCanceled, attempt, errClassCanceled, "canceled between attempts")
			}
		}
	}
	return res
}

func (p *prober) tryOnce(ctx context.Context, t probeTarget) (status, ErrorClass, string) {
	if ctx.Err() != nil {
		return statusCanceled, errClassCanceled, "canceled"
	}

	reqCtx := ctx
	cancel := func() {}
	if p.Timeout > 0 {
		reqCtx, cancel = context.WithTimeout(ctx, p.Timeout)
	}
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, p.Method, t.URL, nil)
	if err != nil {
		// Do not echo the request URL: it contains the target address.
		return statusError, errClassInput, "invalid input"
	}
	req.Header.Add("Connection", "close")
	req.Close = true

	resp, err := p.Client.Do(req)
	if err != nil {
		st, class := classifyProbeError(err)
		if ctx.Err() != nil && st != statusTimeout {
			return statusCanceled, errClassCanceled, "canceled"
		}
		return st, class, sanitiseError(err)
	}
	defer resp.Body.Close()

	// Drain a bounded amount so the connection closes cleanly, but never let
	// a trickling body occupy a worker past the deadline.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 32*1024))
	return statusReachable, errClassNone, ""
}

func (p *prober) commit(idx int, res probeResult, results []probeResult, done *int64, total int) {
	results[idx] = res
	n := int(atomic.AddInt64(done, 1))
	// A panic in a user callback must never escape commit: if it did, the
	// group's "already committed" flag could stay false and the target would
	// be committed twice. Callback failures are isolated here instead.
	defer func() { _ = recover() }()
	if p.OnResult != nil {
		p.OnResult(res)
	}
	if p.OnProgress != nil {
		p.OnProgress(n, total)
	}
}

func terminalResult(t probeTarget, st status, attempts int, class ErrorClass, msg string) probeResult {
	return probeResult{Target: t, Status: st, Attempts: attempts, LastError: class, Error: msg}
}

func panicResult(t probeTarget) probeResult {
	return probeResult{
		Target:    t,
		Status:    statusError,
		Attempts:  1,
		LastError: errClassPanic,
		Error:     "probe panic",
	}
}

// --- plan construction ---------------------------------------------------

// targetSpec is a raw, un-normalised probe request: one domain plus an
// optional explicit port.
type targetSpec struct {
	Host string
}

type groupBuilder struct {
	hostPort string
	https    bool
	http     bool
}

type planBuilder struct {
	groups []*groupBuilder
	byKey  map[string]*groupBuilder
}

func newPlanBuilder() *planBuilder {
	return &planBuilder{byKey: make(map[string]*groupBuilder)}
}

// add records one scheme/port probe for a domain. Repeated URLs are merged,
// so the same target is never probed twice in one run.
func (b *planBuilder) add(host, scheme, port string) {
	hostPort := joinHostPort(host, port)
	key := strings.ToLower(hostPort)
	g := b.byKey[key]
	if g == nil {
		g = &groupBuilder{hostPort: hostPort}
		b.byKey[key] = g
		b.groups = append(b.groups, g)
	}
	switch scheme {
	case "https":
		g.https = true
	case "http":
		g.http = true
	}
}

func (b *planBuilder) build() *probePlan {
	plan := &probePlan{}
	for _, g := range b.groups {
		pg := &probeGroup{HostPort: g.hostPort, HTTPSIndex: -1, HTTPIndex: -1}
		if g.https {
			pg.HTTPSIndex = len(plan.Targets)
			plan.Targets = append(plan.Targets, probeTarget{
				Index:  len(plan.Targets),
				Scheme: "https",
				Host:   g.hostPort,
				URL:    "https://" + g.hostPort,
			})
		}
		if g.http {
			pg.HTTPIndex = len(plan.Targets)
			plan.Targets = append(plan.Targets, probeTarget{
				Index:  len(plan.Targets),
				Scheme: "http",
				Host:   g.hostPort,
				URL:    "http://" + g.hostPort,
			})
		}
		plan.Groups = append(plan.Groups, pg)
	}
	return plan
}

// joinHostPort attaches an explicit port to a domain. When the domain already
// carries a port, the explicit probe port replaces it.
func joinHostPort(host, port string) string {
	if port == "" {
		return host
	}
	h := host
	if hostOnly, _, err := net.SplitHostPort(host); err == nil {
		h = hostOnly
	}
	return net.JoinHostPort(h, port)
}

// buildPlan turns domains plus -p probe specs into a deterministic target
// plan. Ordering is: groups in first-seen input order; within a group HTTPS
// before HTTP.
func buildPlan(domains, probes []string, skipDefault bool) *probePlan {
	b := newPlanBuilder()
	for _, domain := range domains {
		// Preserve the original tool's case-insensitivity.
		domain = strings.ToLower(strings.TrimSpace(domain))
		if domain == "" {
			continue
		}
		if !skipDefault {
			// HTTPS target with an HTTP fallback, as in the original tool.
			b.add(domain, "https", "")
			b.add(domain, "http", "")
		}
		for _, probe := range probes {
			switch probe {
			case "xlarge":
				for _, port := range xlargePorts {
					b.add(domain, "https", port)
					b.add(domain, "http", port)
				}
			case "large":
				for _, port := range largePorts {
					b.add(domain, "https", port)
					b.add(domain, "http", port)
				}
			default:
				pair := strings.SplitN(probe, ":", 2)
				if len(pair) != 2 || pair[1] == "" {
					continue
				}
				// Preserve the original behaviour: anything that is not
				// explicitly "https" is treated as an HTTP probe.
				if strings.ToLower(pair[0]) == "https" {
					b.add(domain, "https", pair[1])
					b.add(domain, "http", pair[1])
				} else {
					b.add(domain, "http", pair[1])
				}
			}
		}
	}
	return b.build()
}

// Port templates kept from the original tool.
var largePorts = []string{"81", "591", "2082", "2087", "2095", "2096", "3000", "8000", "8001", "8008", "8080", "8083", "8443", "8834", "8888"}

var xlargePorts = []string{"81", "300", "591", "593", "832", "981", "1010", "1311", "2082", "2087", "2095", "2096", "2480", "3000", "3128", "3333", "4243", "4567", "4711", "4712", "4993", "5000", "5104", "5108", "5800", "6543", "7000", "7396", "7474", "8000", "8001", "8008", "8014", "8042", "8069", "8080", "8081", "8088", "8090", "8091", "8118", "8123", "8172", "8222", "8243", "8280", "8281", "8333", "8443", "8500", "8834", "8880", "8888", "8983", "9000", "9043", "9060", "9080", "9090", "9091", "9200", "9443", "9800", "9981", "12443", "16080", "18091", "18092", "20720", "28017"}
