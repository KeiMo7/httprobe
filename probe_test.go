package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// --- test servers --------------------------------------------------------

// startHTTPListener starts a real HTTP listener on 127.0.0.1 and returns its
// port. The listener is closed when the test ends.
func startHTTPListener(t *testing.T) string {
	return startHTTPListenerOn(t, "127.0.0.1:0")
}

// startWildcardHTTPListener binds all local addresses so 127.0.0.0/8 targets
// are reachable.
func startWildcardHTTPListener(t *testing.T) string {
	return startHTTPListenerOn(t, "0.0.0.0:0")
}

func startHTTPListenerOn(t *testing.T, addr string) string {
	t.Helper()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintln(w, "ok")
		}),
		ReadHeaderTimeout: 2 * time.Second,
	}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}
	return port
}

// startTLSListener starts a TLS listener so HTTPS probes can succeed.
func startTLSListener(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	cert, err := selfSignedCert()
	if err != nil {
		t.Fatalf("self-signed cert: %v", err)
	}
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintln(w, "ok")
		}),
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
		},
		ReadHeaderTimeout: 2 * time.Second,
	}
	go srv.ServeTLS(ln, "", "")
	t.Cleanup(func() { srv.Close() })
	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}
	return port
}

// startTimeoutListener accepts TCP connections but never speaks HTTP, so the
// probe hits its deadline. Connections are held open until cleanup.
func startTimeoutListener(t *testing.T) string {
	return startTimeoutListenerOn(t, "127.0.0.1:0")
}

// startWildcardTimeoutListener accepts on all local addresses so a whole batch
// of 127.0.0.0/8 targets can be made to hit the deadline.
func startWildcardTimeoutListener(t *testing.T) string {
	return startTimeoutListenerOn(t, "0.0.0.0:0")
}

func startTimeoutListenerOn(t *testing.T, addr string) string {
	t.Helper()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	var mu sync.Mutex
	var conns []net.Conn
	done := make(chan struct{})
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
			go func(c net.Conn) {
				// Hold the connection, never respond.
				<-done
				c.Close()
			}(c)
		}
	}()
	t.Cleanup(func() {
		close(done)
		ln.Close()
		mu.Lock()
		for _, c := range conns {
			c.Close()
		}
		mu.Unlock()
	})
	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}
	return port
}

// closedPort returns a port that is guaranteed to refuse connections.
func closedPort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}
	ln.Close()
	return port
}

func testProber(t *testing.T, concurrency, attempts int, timeout time.Duration) *prober {
	t.Helper()
	client := &http.Client{
		Transport: &http.Transport{
			DisableKeepAlives: true,
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			DialContext: (&net.Dialer{
				Timeout:   timeout,
				KeepAlive: time.Second,
			}).DialContext,
		},
		Timeout: timeout,
	}
	return newProber(client, http.MethodGet, timeout, concurrency, attempts)
}

// --- scenario 1: local listeners cover reachable/refused/timeout ---------

func TestProbeClassifiesReachableRefusedTimeout(t *testing.T) {
	httpPort := startHTTPListener(t)
	timeoutPort := startTimeoutListener(t)
	refusedPort := closedPort(t)

	plans := buildPlan([]string{"127.0.0.1"}, []string{
		"http:" + httpPort,
		"http:" + refusedPort,
		"http:" + timeoutPort,
	}, true)

	p := testProber(t, 4, 1, 300*time.Millisecond)
	results := p.Probe(context.Background(), plans)

	byURL := map[string]probeResult{}
	for _, r := range results {
		byURL[r.Target.URL] = r
	}

	if got := byURL["http://127.0.0.1:"+httpPort].Status; got != statusReachable {
		t.Errorf("reachable probe: got status %q, want %q", got, statusReachable)
	}
	if got := byURL["http://127.0.0.1:"+refusedPort].Status; got != statusRefused {
		t.Errorf("refused probe: got status %q, want %q", got, statusRefused)
	}
	if got := byURL["http://127.0.0.1:"+refusedPort].LastError; got != errClassRefused {
		t.Errorf("refused probe: got error class %q, want %q", got, errClassRefused)
	}
	if got := byURL["http://127.0.0.1:"+timeoutPort].Status; got != statusTimeout {
		t.Errorf("timeout probe: got status %q, want %q", got, statusTimeout)
	}
	if got := byURL["http://127.0.0.1:"+timeoutPort].LastError; got != errClassTimeout {
		t.Errorf("timeout probe: got error class %q, want %q", got, errClassTimeout)
	}

	for _, r := range results {
		if r.Attempts < 1 {
			t.Errorf("%s: attempts = %d, want >= 1", r.Target.URL, r.Attempts)
		}
		if r.LastError == "" && r.Status != statusReachable {
			t.Errorf("%s: non-reachable result has empty last error", r.Target.URL)
		}
	}
}

func TestClassifyProbeErrorByTypeNotElapsedTime(t *testing.T) {
	// A quick connection reset must not be called a timeout just because it
	// was fast, and a refusal must be recognised from the errno.
	if st, class := classifyProbeError(syscall.ECONNREFUSED); st != statusRefused || class != errClassRefused {
		t.Errorf("ECONNREFUSED: got (%q,%q)", st, class)
	}
	if st, class := classifyProbeError(context.DeadlineExceeded); st != statusTimeout || class != errClassTimeout {
		t.Errorf("DeadlineExceeded: got (%q,%q)", st, class)
	}
	timeoutErr := &net.DNSError{Err: "i/o timeout", IsTimeout: true}
	if st, class := classifyProbeError(timeoutErr); st != statusTimeout || class != errClassTimeout {
		t.Errorf("DNS timeout: got (%q,%q)", st, class)
	}
	reset := &net.OpError{Op: "read", Net: "tcp", Err: syscall.ECONNRESET}
	if st, _ := classifyProbeError(reset); st != statusError {
		t.Errorf("ECONNRESET: got %q, want %q", st, statusError)
	}
}

// --- scenario 2: repeated runs have identical result sets -----------------

func TestRepeatedRunsProduceIdenticalResultSets(t *testing.T) {
	httpPort := startHTTPListener(t)
	refusedPort := closedPort(t)
	timeoutPort := startTimeoutListener(t)

	domains := []string{"127.0.0.1"}
	probes := []string{"http:" + httpPort, "http:" + refusedPort, "http:" + timeoutPort}
	plan := buildPlan(domains, probes, true)
	p := testProber(t, 8, 1, 250*time.Millisecond)

	run := func() []string {
		results := p.Probe(context.Background(), plan)
		var got []string
		for _, r := range results {
			got = append(got, fmt.Sprintf("%s=%s", r.Target.URL, r.Status))
		}
		return got
	}

	first := run()
	second := run()
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("repeated runs differ:\nfirst:  %v\nsecond: %v", first, second)
	}
	// Identifier set comparison, not just ordering.
	asSet := func(in []string) []string {
		out := append([]string(nil), in...)
		sort.Strings(out)
		return out
	}
	if !reflect.DeepEqual(asSet(first), asSet(second)) {
		t.Fatalf("result sets differ:\nfirst:  %v\nsecond: %v", first, second)
	}
}

// --- scenario 3: concurrency limit must not skip targets ------------------

func TestConcurrencyLimitDoesNotSkipTargets(t *testing.T) {
	httpPort := startHTTPListener(t)

	const domainCount = 40
	domains := make([]string, domainCount)
	for i := range domains {
		domains[i] = "127.0.0.1"
	}

	// buildPlan dedups identical host:port pairs, so use distinct hosts that
	// all resolve to loopback (127.0.0.0/8) to get many distinct targets.
	for i := 0; i < domainCount; i++ {
		domains[i] = fmt.Sprintf("127.0.0.%d", i+2)
	}

	plan := buildPlan(domains, []string{"http:" + httpPort}, true)
	if len(plan.Targets) != domainCount {
		t.Fatalf("expected %d targets, got %d", domainCount, len(plan.Targets))
	}

	for _, concurrency := range []int{1, 2, 7, 40} {
		p := testProber(t, concurrency, 1, 2*time.Second)
		var attempted int64
		p.OnResult = func(r probeResult) {
			atomic.AddInt64(&attempted, 1)
		}
		results := p.Probe(context.Background(), plan)

		if int(attempted) != domainCount {
			t.Errorf("concurrency=%d: attempted %d targets, want %d", concurrency, attempted, domainCount)
		}
		if len(results) != domainCount {
			t.Fatalf("concurrency=%d: got %d results, want %d", concurrency, len(results), domainCount)
		}
		for i, r := range results {
			if r.Target.Index != i {
				t.Errorf("concurrency=%d: result %d has index %d", concurrency, i, r.Target.Index)
			}
			if r.Attempts < 1 {
				t.Errorf("concurrency=%d: %s was not attempted (attempts=%d, status=%q)",
					concurrency, r.Target.URL, r.Attempts, r.Status)
			}
		}
		if got := p.Slots.InUse(); got != 0 {
			t.Errorf("concurrency=%d: %d slots leaked", concurrency, got)
		}
	}
}

func TestEveryTargetHasTerminalStateOnLargeBatch(t *testing.T) {
	httpPort := startHTTPListener(t)
	refusedPort := closedPort(t)

	domains := make([]string, 120)
	for i := range domains {
		domains[i] = fmt.Sprintf("127.0.0.%d", (i%250)+2)
	}
	probes := []string{"http:" + httpPort, "http:" + refusedPort}
	plan := buildPlan(domains, probes, true)

	p := testProber(t, 16, 1, 1500*time.Millisecond)
	results := p.Probe(context.Background(), plan)

	if len(results) != len(plan.Targets) {
		t.Fatalf("got %d results for %d targets", len(results), len(plan.Targets))
	}
	valid := map[status]bool{
		statusReachable: true, statusRefused: true, statusTimeout: true,
		statusError: true, statusCanceled: true, statusSkipped: true,
	}
	for i, r := range results {
		if !valid[r.Status] {
			t.Errorf("target %d (%s) has non-terminal status %q", i, r.Target.URL, r.Status)
		}
		if r.Attempts < 1 {
			t.Errorf("target %d (%s) has no attempt recorded", i, r.Target.URL)
		}
	}
}

// --- scenario 4: stable ordering with multiple reachable addresses --------

func TestOutputOrderIsStableForMultipleReachableAddresses(t *testing.T) {
	portA := startHTTPListener(t)
	portB := startHTTPListener(t)
	portC := startHTTPListener(t)

	// Deliberately unsorted input; every target is reachable, so the output
	// must be exactly the plan order on every run.
	domains := []string{"127.0.0.1"}
	probes := []string{"http:" + portC, "http:" + portA, "http:" + portB}
	plan := buildPlan(domains, probes, true)

	var want []string
	for _, target := range plan.Targets {
		want = append(want, target.URL)
	}

	p := testProber(t, 16, 1, 2*time.Second)
	for run := 0; run < 3; run++ {
		results := p.Probe(context.Background(), plan)
		var urls []string
		for _, r := range results {
			if r.Status == statusReachable {
				urls = append(urls, r.Target.URL)
			}
		}
		if !reflect.DeepEqual(urls, want) {
			t.Fatalf("run %d output order differs from plan order:\ngot:  %v\nwant: %v", run, urls, want)
		}
	}
}

// --- scenario 5: attempts and last error are reported ---------------------

func TestRetryRecordsAttemptsAndLastError(t *testing.T) {
	refusedPort := closedPort(t)
	plan := buildPlan([]string{"127.0.0.1"}, []string{"http:" + refusedPort}, true)
	p := testProber(t, 2, 3, 300*time.Millisecond)
	p.RetryDelay = time.Millisecond

	results := p.Probe(context.Background(), plan)
	if len(results) != 1 {
		t.Fatalf("got %d results", len(results))
	}
	r := results[0]
	if r.Attempts != 3 {
		t.Errorf("attempts = %d, want 3", r.Attempts)
	}
	if r.LastError != errClassRefused {
		t.Errorf("last error = %q, want %q", r.LastError, errClassRefused)
	}
}

// --- scenario 6: no stale state between runs -----------------------------

func TestStateChangeBetweenRunsIsReflected(t *testing.T) {
	// First run: nothing listening -> refused. Second run: a listener is up on
	// the same port -> reachable.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	plan := buildPlan([]string{"127.0.0.1"}, []string{fmt.Sprintf("http:%d", port)}, true)
	p := testProber(t, 2, 1, 300*time.Millisecond)

	before := p.Probe(context.Background(), plan)
	if before[0].Status != statusRefused {
		t.Fatalf("expected refused before listener starts, got %q", before[0].Status)
	}

	ln2, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Skipf("could not rebind port %d: %v", port, err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})}
	go srv.Serve(ln2)
	t.Cleanup(func() { srv.Close() })

	var after []probeResult
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		after = p.Probe(context.Background(), plan)
		if after[0].Status == statusReachable {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if after[0].Status != statusReachable {
		t.Fatalf("expected reachable after listener starts, got %q", after[0].Status)
	}
}

// --- limiter and cancellation -------------------------------------------

func TestLimiterDoubleReleaseSelfHeals(t *testing.T) {
	l := newLimiter(2)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	a, err := l.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	b, err := l.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if l.InUse() != 2 {
		t.Fatalf("in use = %d, want 2", l.InUse())
	}

	// Abnormal double release: the second call must be ignored, not return a
	// slot that was never taken. b is still held, so one slot stays in use.
	a.Release()
	a.Release()
	if got := l.InUse(); got != 1 {
		t.Fatalf("after double release in use = %d, want 1", got)
	}
	if got := l.Capacity(); got != 2 {
		t.Fatalf("capacity changed to %d", got)
	}

	// The freed slot must still be schedulable afterwards; the double release
	// must not have starved later targets.
	c, err := l.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire after double release: %v", err)
	}
	if got := l.InUse(); got != 2 {
		t.Fatalf("in use = %d, want 2", got)
	}

	// Release both held slots; a fresh acquire must succeed.
	b.Release()
	c.Release()
	if got := l.InUse(); got != 0 {
		t.Fatalf("final in use = %d, want 0", got)
	}
	d, err := l.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire after all releases: %v", err)
	}
	d.Release()
}

func TestLimiterCancelledWaiterDoesNotLeakSlot(t *testing.T) {
	l := newLimiter(1)
	held, err := l.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := l.Acquire(ctx); err == nil {
		t.Fatal("expected cancellation error")
	}
	held.Release()
	if got := l.InUse(); got != 0 {
		t.Fatalf("in use = %d, want 0", got)
	}
}

func TestCancelKeepsCompletedResults(t *testing.T) {
	httpPort := startHTTPListener(t)
	timeoutPort := startWildcardTimeoutListener(t)

	// Many slow targets so cancellation happens mid-batch.
	domains := make([]string, 60)
	for i := range domains {
		domains[i] = fmt.Sprintf("127.0.0.%d", (i%250)+2)
	}
	// Interleave a fast reachable port with a slow port so part of the batch
	// finishes before cancellation, and the rest is in flight.
	plan := buildPlan(domains, []string{"http:" + httpPort, "http:" + timeoutPort}, true)

	p := testProber(t, 4, 1, 5*time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(120 * time.Millisecond)
		cancel()
	}()

	results := p.Probe(ctx, plan)
	if len(results) != len(plan.Targets) {
		t.Fatalf("got %d results for %d targets", len(results), len(plan.Targets))
	}
	var done, cancelled int
	for _, r := range results {
		if r.Status == statusCanceled {
			cancelled++
		} else {
			done++
		}
		if r.Status == "" {
			t.Errorf("target %s has empty terminal status", r.Target.URL)
		}
	}
	if done == 0 {
		t.Fatal("expected some results to complete before cancellation")
	}
	if cancelled == 0 {
		t.Fatal("expected some targets to be explicitly cancelled")
	}
	t.Logf("completed before cancel: %d, cancelled: %d", done, cancelled)
}

func TestPanicInsideProbeIsIsolated(t *testing.T) {
	// A nil Client would panic inside tryOnce; the prober must convert that
	// to a terminal error for the target and keep processing others.
	p := &prober{
		Client:      nil,
		Method:      http.MethodGet,
		Timeout:     time.Second,
		Attempts:    1,
		Concurrency: 2,
		Slots:       newLimiter(2),
	}
	plan := buildPlan([]string{"127.0.0.1"}, []string{"http:1"}, true)
	results := p.Probe(context.Background(), plan)
	if len(results) != 1 {
		t.Fatalf("got %d results", len(results))
	}
	if results[0].Status != statusError || results[0].LastError != errClassPanic {
		t.Fatalf("panic result = %+v", results[0])
	}
}

// TestPanicIsolationDoesNotAffectOtherTargets verifies that one panicking
// target does not abort the batch or leave other targets without a result.
func TestPanicIsolationDoesNotAffectOtherTargets(t *testing.T) {
	httpPort := startWildcardHTTPListener(t)

	// A RoundTripper runs synchronously on our worker goroutine, so its panic
	// is inside the prober's isolation boundary. (A panic in a dialer
	// callback happens on an net/http-owned goroutine and is not recoverable
	// by any caller.)
	client := &http.Client{Transport: panicTransport{
		inner: &http.Transport{
			DisableKeepAlives: true,
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		},
		panicOn: "127.0.0.99",
	}}

	domains := []string{"127.0.0.99", "127.0.0.2", "127.0.0.3"}
	plan := buildPlan(domains, []string{"http:" + httpPort}, true)
	p := newProber(client, http.MethodGet, 2*time.Second, 3, 1)

	results := p.Probe(context.Background(), plan)
	if len(results) != 3 {
		t.Fatalf("got %d results, want 3", len(results))
	}
	if results[0].Status != statusError {
		t.Errorf("panicking target: status = %q, want %q", results[0].Status, statusError)
	}
	for _, r := range results[1:] {
		if r.Status != statusReachable {
			t.Errorf("healthy target %s: status = %q, want reachable", r.Target.URL, r.Status)
		}
	}
	if got := p.Slots.InUse(); got != 0 {
		t.Errorf("slots leaked: %d", got)
	}
}

type panicTransport struct {
	inner   http.RoundTripper
	panicOn string
}

func (p panicTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if strings.Contains(req.URL.Host, p.panicOn) {
		panic("injected transport panic")
	}
	return p.inner.RoundTrip(req)
}

// --- output: stable ordering, JSON fields, write failures ----------------

func TestOrderedWriterEmitsInTargetOrder(t *testing.T) {
	var buf strings.Builder
	sink := &streamSink{w: newBufWriter(&buf), path: "-", out: &buf}
	ow := newOrderedWriter(sink)

	targets := make([]probeTarget, 5)
	for i := range targets {
		targets[i] = probeTarget{Index: i, URL: fmt.Sprintf("http://h%d", i)}
	}
	for _, i := range []int{3, 1, 4, 0, 2} {
		ow.Record(probeResult{Target: targets[i], Status: statusReachable})
	}
	if err := ow.sink.Close(); err != nil {
		t.Fatal(err)
	}
	want := "http://h0\nhttp://h1\nhttp://h2\nhttp://h3\nhttp://h4\n"
	if buf.String() != want {
		t.Fatalf("output = %q, want %q", buf.String(), want)
	}
}

func TestJSONOutputIncludesAttemptsAndLastError(t *testing.T) {
	r := probeResult{
		Target:    probeTarget{Index: 0, URL: "http://example.test"},
		Status:    statusTimeout,
		Attempts:  3,
		LastError: errClassTimeout,
	}
	line := formatJSON(r)
	for _, want := range []string{`"attempts":3`, `"last_error":"timeout"`, `"status":"timeout"`} {
		if !strings.Contains(line, want) {
			t.Errorf("json %q missing %q", line, want)
		}
	}
}

func TestSanitiseErrorDoesNotLeakAddress(t *testing.T) {
	addr := "http://10.1.2.3:8443/path"
	err := &urlErrorWithAddr{msg: addr, inner: syscall.ECONNREFUSED}
	got := sanitiseError(err)
	if strings.Contains(got, "10.1.2.3") || strings.Contains(got, "8443") {
		t.Fatalf("sanitised error leaked target address: %q", got)
	}
	if got != "connection refused" {
		t.Fatalf("got %q, want %q", got, "connection refused")
	}
}

func TestOutputWriteFailureKeepsCompletedResults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.txt")
	sink, err := newResultSink(path, false, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	fs := sink.(*fileSink)
	// Make the underlying buffered writer fail on the next write.
	fs.streamSink.w = failingWriter{}

	_ = sink.WriteResult(probeResult{Target: probeTarget{URL: "http://a"}, Status: statusReachable})
	closeErr := sink.Close()
	if closeErr == nil {
		t.Fatal("expected close error from failing writer")
	}
	entries, _ := os.ReadDir(dir)
	var tmpFiles []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".httprobe-") {
			tmpFiles = append(tmpFiles, e.Name())
		}
	}
	if len(tmpFiles) == 0 {
		t.Fatalf("expected partial temp file to be preserved, dir contains %v", entries)
	}
}

// --- input reading -------------------------------------------------------

func TestReadDomainsReportsLinePosition(t *testing.T) {
	in := "good.example\n\nbad\x00line\ngood2.example\n"
	domains, issues := readDomains(strings.NewReader(in), 1024)
	if len(issues) != 0 {
		t.Fatalf("unexpected issues: %v", issues)
	}
	if !reflect.DeepEqual(domains, []string{"good.example", "bad\x00line", "good2.example"}) {
		t.Fatalf("domains = %v", domains)
	}

	// Overlong line must be reported with its position, not skipped silently.
	long := strings.Repeat("x", 20)
	_, issues = readDomains(strings.NewReader("ok\n"+long+"\n"), 10)
	if len(issues) != 1 || issues[0].Line != 2 {
		t.Fatalf("issues = %v, want one issue on line 2", issues)
	}
	if strings.Contains(issues[0].Error(), long) {
		t.Fatalf("issue leaked line content: %v", issues[0])
	}
}

// --- run(): CLI compatibility -------------------------------------------

func TestRunPreservesSingleTargetOutput(t *testing.T) {
	port := startHTTPListener(t)
	var out, errBuf strings.Builder
	code := run([]string{"-s", "-p", "http:" + port, "-t", "2000"},
		strings.NewReader("127.0.0.1\n"), &out, &errBuf)
	if code != 0 {
		t.Fatalf("exit code = %d, stderr=%s", code, errBuf.String())
	}
	want := "http://127.0.0.1:" + port + "\n"
	if out.String() != want {
		t.Fatalf("stdout = %q, want %q", out.String(), want)
	}
}

func TestRunPrefersHTTPSKeepsBehaviour(t *testing.T) {
	tlsPort := startTLSListener(t)
	var out, errBuf strings.Builder
	code := run([]string{"-s", "-p", "https:" + tlsPort, "--prefer-https", "-t", "2000"},
		strings.NewReader("127.0.0.1\n"), &out, &errBuf)
	if code != 0 {
		t.Fatalf("exit code = %d, stderr=%s", code, errBuf.String())
	}
	want := "https://127.0.0.1:" + tlsPort + "\n"
	if out.String() != want {
		t.Fatalf("stdout = %q, want %q", out.String(), want)
	}
}

func TestRunLowConcurrencyDoesNotDropTargets(t *testing.T) {
	// Regression for concurrency/2 == 0: -c 1 must still probe.
	port := startHTTPListener(t)
	var out, errBuf strings.Builder
	code := run([]string{"-s", "-p", "http:" + port, "-c", "1", "-t", "2000"},
		strings.NewReader("127.0.0.1\n"), &out, &errBuf)
	if code != 0 {
		t.Fatalf("exit code = %d, stderr=%s", code, errBuf.String())
	}
	if !strings.Contains(out.String(), "http://127.0.0.1:"+port) {
		t.Fatalf("target dropped at -c 1: stdout=%q", out.String())
	}
}

// --- helpers -------------------------------------------------------------

type failingWriter struct{}

func (failingWriter) WriteString(string) (int, error) { return 0, errors.New("disk full") }
func (failingWriter) Flush() error                    { return nil }

type bufWriter struct{ b *strings.Builder }

func newBufWriter(b *strings.Builder) *bufWriter       { return &bufWriter{b: b} }
func (w *bufWriter) WriteString(s string) (int, error) { return w.b.WriteString(s) }
func (w *bufWriter) Flush() error                      { return nil }

// urlErrorWithAddr mimics url.Error's message, which embeds the full URL.
type urlErrorWithAddr struct {
	msg   string
	inner error
}

func (e *urlErrorWithAddr) Error() string { return e.msg }
func (e *urlErrorWithAddr) Unwrap() error { return e.inner }

// selfSignedCert generates an in-memory certificate for the TLS test listener.
func selfSignedCert() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}
