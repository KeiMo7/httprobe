package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

const (
	testPhase   = 300 * time.Millisecond
	testOverall = 2 * testPhase
)

func testProber() *Prober {
	return &Prober{
		connectPhaseTimeout: testPhase,
		readPhaseTimeout:    testPhase,
		overallDeadline:     testOverall,
		maxRetries:          1,
		method:              "GET",
		verifyCerts:         true,
	}
}

// ---------------------------------------------------------------------------
// local peer fixtures: the four peer behaviors required by acceptance test 1
// ---------------------------------------------------------------------------

// blackholeAddr returns a local address that answers no further handshake
// packets, so dials burn the connect-phase budget.
//
// Implementation: a raw TCP socket with listen backlog 1 that is *never*
// accepted from, plus enough established connections to fill the single-slot
// accept queue. With the queue full, the kernel drops subsequent SYNs on
// loopback (verified empirically: every probe then fails with i/o timeout at
// the connect stage). Wrapping the fd in a net.Listener would drain the queue
// via implicit accepts and defeat this, so it stays a bare syscall socket.
func blackholeAddr(t *testing.T) string {
	t.Helper()
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("socket: %v", err)
	}
	if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
		t.Fatalf("setsockopt: %v", err)
	}
	if err := syscall.Bind(fd, &syscall.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		t.Fatalf("bind: %v", err)
	}
	if err := syscall.Listen(fd, 1); err != nil {
		t.Fatalf("listen: %v", err)
	}
	sa, err := syscall.Getsockname(fd)
	if err != nil {
		t.Fatalf("getsockname: %v", err)
	}
	port := sa.(*syscall.SockaddrInet4).Port
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	t.Cleanup(func() { syscall.Close(fd) })

	// Fill the accept queue; never accept on fd. Two established connections
	// suffice for a backlog of 1.
	var held []net.Conn
	for i := 0; i < 4; i++ {
		c, err := net.DialTimeout("tcp", addr, time.Second)
		if err != nil {
			break
		}
		held = append(held, c)
	}
	if len(held) == 0 {
		t.Skip("could not fill blackhole accept queue in this environment")
	}
	t.Cleanup(func() {
		for _, c := range held {
			c.Close()
		}
	})

	// Verify the blackhole property: a fresh dial must time out at connect.
	probe, err := net.DialTimeout("tcp", addr, 250*time.Millisecond)
	if err == nil {
		probe.Close()
		t.Skip("blackhole address accepted a connection; environment does not drop SYNs on full queue")
	}
	var ne net.Error
	if !(errors.As(err, &ne) && ne.Timeout()) {
		t.Skipf("expected connect timeout, got %v", err)
	}
	return addr
}

// silentListener accepts connections and never writes anything back, so the
// peer stalls in the response-reading (or TLS handshake) phase.
func silentListener(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				time.Sleep(5 * time.Second)
			}(c)
		}
	}()
	return ln
}

// closeOnAcceptListener accepts then immediately closes, aborting any TLS
// negotiation mid-flight.
func closeOnAcceptListener(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	return ln
}

func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	keyDer, _ := x509.MarshalECPrivateKey(key)
	cert, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDer}),
	)
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	return cert
}

// tlsListener starts a TLS server with the given config tweaks.
func tlsListener(t *testing.T, cfg *tls.Config) net.Listener {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatalf("tls listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.(*tls.Conn).Handshake()
			}(c)
		}
	}()
	return ln
}

func refusedAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

// ---------------------------------------------------------------------------
// acceptance test 1: the four peer behaviors land in distinct categories
// ---------------------------------------------------------------------------

func TestClassifications(t *testing.T) {
	cases := []struct {
		name    string
		tls     bool
		setup   func(t *testing.T) string
		modify  func(p *Prober)
		want    Category
		wantErr bool
	}{
		{
			name:  "no handshake response -> connect_timeout",
			tls:   false,
			setup: blackholeAddr,
			want:  CategoryConnectTimeout,
		},
		{
			name:  "connected but no response headers -> read_timeout",
			tls:   false,
			setup: func(t *testing.T) string { return silentListener(t).Addr().String() },
			want:  CategoryReadTimeout,
		},
		{
			name:    "connected but TLS negotiation aborted -> unknown with raw error",
			tls:     true,
			setup:   func(t *testing.T) string { return closeOnAcceptListener(t).Addr().String() },
			want:    CategoryUnknown,
			wantErr: true,
		},
		{
			name: "TLS protocol version mismatch -> tls_protocol",
			tls:  true,
			setup: func(t *testing.T) string {
				ln := tlsListener(t, &tls.Config{
					Certificates: []tls.Certificate{selfSignedCert(t)},
					MaxVersion:   tls.VersionTLS12,
				})
				return ln.Addr().String()
			},
			modify: func(p *Prober) { p.tlsMinVersion = tls.VersionTLS13 },
			want:   CategoryTLSProtocol,
		},
		{
			name: "self-signed certificate -> tls_certificate",
			tls:  true,
			setup: func(t *testing.T) string {
				ln := tlsListener(t, &tls.Config{Certificates: []tls.Certificate{selfSignedCert(t)}})
				return ln.Addr().String()
			},
			want: CategoryTLSCertificate,
		},
		{
			name:  "explicit refusal -> connection_refused",
			tls:   false,
			setup: refusedAddr,
			want:  CategoryConnectionRefused,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := testProber()
			if tc.modify != nil {
				tc.modify(p)
			}
			scheme := "http"
			if tc.tls {
				scheme = "https"
			}
			target := scheme + "://" + tc.setup(t) + "/"
			v := p.Probe(context.Background(), target)
			if v.Category != tc.want {
				t.Fatalf("category = %q, want %q (err=%q)", v.Category, tc.want, v.Err)
			}
			if tc.wantErr && v.Err == "" {
				t.Fatalf("expected raw error text retained for %q, got empty Err", tc.want)
			}
			// Deterministic conclusions never spend a retry.
			if v.Category == CategoryConnectionRefused && v.Retries != 0 {
				t.Fatalf("refused target retried %d times", v.Retries)
			}
		})
	}
}

func TestDNSErrorIsLocalSide(t *testing.T) {
	p := testProber()
	v := p.Probe(context.Background(), "http://nonexistent-uid71-test.invalid:80/")
	if v.Category != CategoryDNSError {
		t.Fatalf("category = %q, want dns_error (err=%q)", v.Category, v.Err)
	}
	if v.Retries != 0 {
		t.Fatalf("DNS failure retried %d times", v.Retries)
	}
}

func TestAvailablePlainAndTLS(t *testing.T) {
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot) // any response counts as available
	}))
	t.Cleanup(plain.Close)

	p := testProber()
	if v := p.Probe(context.Background(), plain.URL); v.Category != CategoryAvailable {
		t.Fatalf("plain probe = %q (%s), want available", v.Category, v.Err)
	}

	secure := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	t.Cleanup(secure.Close)
	p2 := testProber()
	p2.verifyCerts = false // mirror InsecureSkipVerify availability path
	if v := p2.Probe(context.Background(), secure.URL); v.Category != CategoryAvailable {
		t.Fatalf("tls probe = %q (%s), want available", v.Category, v.Err)
	}
}

// acceptance test 2: first attempt hits a retryable class, second succeeds;
// exactly one available verdict, retry count 1.
func TestFlakyFirstTimeoutThenSuccess(t *testing.T) {
	root, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })

	var served int64
	flaky := &firstConnSilentListener{Listener: root, hold: 5 * time.Second}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&served, 1)
	})}
	go srv.Serve(flaky)
	t.Cleanup(func() { srv.Close() })

	p := testProber()
	v := p.Probe(context.Background(), "http://"+root.Addr().String()+"/")
	if v.Category != CategoryAvailable {
		t.Fatalf("category = %q (%s), want available", v.Category, v.Err)
	}
	if v.Retries != 1 {
		t.Fatalf("retries = %d, want 1", v.Retries)
	}
	if atomic.LoadInt64(&served) != 1 {
		t.Fatalf("server handled %d requests, want exactly 1 successful one", served)
	}
}

type firstConnSilentListener struct {
	net.Listener
	once sync.Once
	hold time.Duration
}

func (l *firstConnSilentListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	var first bool
	l.once.Do(func() { first = true })
	if first {
		// The first connection must behave as "accepts but never returns
		// anything": block Reads server-side until hold elapses, then close.
		// The client's request Writes still succeed into the kernel buffer,
		// so the failure surfaces strictly in the response-read phase.
		release := make(chan struct{})
		go func() {
			time.Sleep(l.hold)
			close(release)
			c.Close()
		}()
		return &silentReadConn{Conn: c, release: release}, nil
	}
	return c, nil
}

type silentReadConn struct {
	net.Conn
	release chan struct{}
}

func (c *silentReadConn) Read(p []byte) (int, error) {
	<-c.release
	return 0, net.ErrClosed
}

// acceptance: retries exhausted -> last attempt's category retained, retry
// count attached, deterministic verdict never downgraded to unknown.
func TestRetriesExhaustedKeepsLastCategory(t *testing.T) {
	ln := silentListener(t)
	p := testProber()
	v := p.Probe(context.Background(), "http://"+ln.Addr().String()+"/")
	if v.Category != CategoryReadTimeout {
		t.Fatalf("category = %q, want read_timeout", v.Category)
	}
	if v.Retries != 1 {
		t.Fatalf("retries = %d, want 1", v.Retries)
	}
}

// acceptance: classification must be repeatable — same input, same category.
func TestDeterministicClassification(t *testing.T) {
	addr := blackholeAddr(t)
	p := testProber()
	for i := 0; i < 3; i++ {
		v := p.Probe(context.Background(), "http://"+addr+"/")
		if v.Category != CategoryConnectTimeout {
			t.Fatalf("run %d: category = %q, want connect_timeout", i, v.Category)
		}
	}
}

// ---------------------------------------------------------------------------
// sink resilience (failure & degradation 3)
// ---------------------------------------------------------------------------

func TestBrokenDiagSinkNeverPanics(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	r.Close() // downstream gone before any write
	sink := NewDiagSink(w)
	for i := 0; i < 100; i++ {
		sink.Emit(&Verdict{Target: "x", Category: CategoryUnknown})
	}
	sink.Close() // must not panic either
}

// ---------------------------------------------------------------------------
// registry: concurrency cannot produce contradictory duplicate records
// (hard constraint 4, degradation 4)
// ---------------------------------------------------------------------------

func TestRegistrySingleProbePerTarget(t *testing.T) {
	var conns int64
	root, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	counting := &countingListener{Listener: root, n: &conns}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.Listener = counting
	srv.Start()
	t.Cleanup(srv.Close)

	reg := newVerdictRegistry()
	p := testProber()
	target := "http://" + root.Addr().String() + "/"

	var wg sync.WaitGroup
	verdicts := make([]*Verdict, 50)
	var leaders int64
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			v, leader := reg.runProbe(p, target)
			verdicts[i] = v
			if leader {
				atomic.AddInt64(&leaders, 1)
			}
		}(i)
	}
	wg.Wait()

	if atomic.LoadInt64(&leaders) != 1 {
		t.Fatalf("got %d leaders, want exactly 1 probe owner", leaders)
	}

	for _, v := range verdicts {
		if v == nil || v.Category != CategoryAvailable {
			t.Fatalf("waiter got wrong verdict: %+v", v)
		}
	}
	if got := atomic.LoadInt64(&conns); got != 1 {
		t.Fatalf("target probed via %d connections, want exactly 1", got)
	}
}

type countingListener struct {
	net.Listener
	n *int64
}

func (l *countingListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err == nil {
		atomic.AddInt64(l.n, 1)
	}
	return c, err
}

// ---------------------------------------------------------------------------
// end-to-end pipeline tests
// ---------------------------------------------------------------------------

// captureStdio runs fn with piped stdin/stdout and returns captured stdout.
func captureStdio(t *testing.T, stdin string, fn func()) string {
	t.Helper()
	oldIn, oldOut := os.Stdin, os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.WriteString(stdin); err != nil {
		t.Fatal(err)
	}
	w.Close()
	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdin = r
	os.Stdout = outW

	var out bytes.Buffer
	done := make(chan struct{})
	go func() {
		b, _ := ioutil.ReadAll(outR)
		out.Write(b)
		close(done)
	}()

	fn()

	outW.Close()
	os.Stdin, os.Stdout = oldIn, oldOut
	r.Close()
	<-done
	return out.String()
}

// acceptance 4: with diagnostics on, stdout still contains available targets
// only and remains consumable by the original one-line-per-target downstream.
// Also covers dedup (one record per target) and HTTPS->HTTP fallback.
func TestPipelineStdoutOnlyAvailableAndDedup(t *testing.T) {
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	t.Cleanup(plain.Close)
	port := strings.TrimPrefix(plain.URL, "http://127.0.0.1:")

	diagFile := filepath.Join(t.TempDir(), "diag.jsonl")
	sink, err := openDiagSink(diagFile)
	if err != nil {
		t.Fatal(err)
	}

	// Same host submitted twice: default probes skipped, one http:port probe
	// per line -> identical target enqueued twice, must produce one record.
	stdin := "127.0.0.1\n127.0.0.1\n"
	stdout := captureStdio(t, stdin, func() {
		runDiagnostics(8, testPhase, 1, "GET", false,
			[]string{fmt.Sprintf("http:%s", port)}, true, sink)
	})
	sink.Close()

	wantLine := fmt.Sprintf("http://127.0.0.1:%s", port)
	if strings.TrimSpace(stdout) != wantLine {
		t.Fatalf("stdout = %q, want exactly one line %q", stdout, wantLine)
	}

	records := readDiag(t, diagFile)
	if len(records) != 1 {
		t.Fatalf("diag records = %d, want exactly 1: %+v", len(records), records)
	}
	if records[0].Category != CategoryAvailable || records[0].Target != wantLine {
		t.Fatalf("unexpected diag record: %+v", records[0])
	}
}

// Different ports of the same host are distinct targets: verdicts never
// overwrite each other (required form 9).
func TestPipelineSameHostDifferentPorts(t *testing.T) {
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	t.Cleanup(good.Close)
	goodPort := strings.TrimPrefix(good.URL, "http://127.0.0.1:")
	badPort := strings.TrimPrefix(refusedAddr(t), "127.0.0.1:")

	diagFile := filepath.Join(t.TempDir(), "diag.jsonl")
	sink, err := openDiagSink(diagFile)
	if err != nil {
		t.Fatal(err)
	}
	stdout := captureStdio(t, "127.0.0.1\n", func() {
		runDiagnostics(8, testPhase, 1, "GET", false,
			[]string{fmt.Sprintf("http:%s", goodPort), fmt.Sprintf("http:%s", badPort)}, true, sink)
	})
	sink.Close()

	if strings.TrimSpace(stdout) != fmt.Sprintf("http://127.0.0.1:%s", goodPort) {
		t.Fatalf("stdout = %q, want only the good port", stdout)
	}
	records := readDiag(t, diagFile)
	byTarget := map[string]Category{}
	for _, v := range records {
		if _, dup := byTarget[v.Target]; dup {
			t.Fatalf("duplicate record for %s", v.Target)
		}
		byTarget[v.Target] = v.Category
	}
	goodTarget := fmt.Sprintf("http://127.0.0.1:%s", goodPort)
	badTarget := fmt.Sprintf("http://127.0.0.1:%s", badPort)
	if byTarget[goodTarget] != CategoryAvailable {
		t.Fatalf("good port verdict = %q, want available", byTarget[goodTarget])
	}
	if byTarget[badTarget] != CategoryConnectionRefused {
		t.Fatalf("refused port verdict = %q, want connection_refused", byTarget[badTarget])
	}
}

// HTTPS fails on a plaintext-only service; the unchanged fallback order still
// surfaces it as available over HTTP, and both verdicts reach diagnostics.
func TestPipelineHTTPSFallbackToHTTP(t *testing.T) {
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	t.Cleanup(plain.Close)
	port := strings.TrimPrefix(plain.URL, "http://127.0.0.1:")

	diagFile := filepath.Join(t.TempDir(), "diag.jsonl")
	sink, err := openDiagSink(diagFile)
	if err != nil {
		t.Fatal(err)
	}
	stdout := captureStdio(t, "127.0.0.1\n", func() {
		runDiagnostics(8, testPhase, 1, "GET", false,
			[]string{fmt.Sprintf("https:%s", port), fmt.Sprintf("http:%s", port)}, true, sink)
	})
	sink.Close()

	if strings.TrimSpace(stdout) != fmt.Sprintf("http://127.0.0.1:%s", port) {
		t.Fatalf("stdout = %q, want http fallback line only", stdout)
	}
	records := readDiag(t, diagFile)
	seen := map[string]Category{}
	for _, v := range records {
		seen[v.Target] = v.Category
	}
	if seen[fmt.Sprintf("https://127.0.0.1:%s", port)] == "" {
		t.Fatalf("missing https failure record: %+v", records)
	}
	if seen[fmt.Sprintf("http://127.0.0.1:%s", port)] != CategoryAvailable {
		t.Fatalf("missing http available record: %+v", records)
	}
}

// Required behavior 3 of "must not break": unrecognized -p entries are
// skipped, and the legacy path keeps working with diagnostics disabled.
func TestLegacyPathSkipsBadProbeEntries(t *testing.T) {
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	t.Cleanup(plain.Close)
	port := strings.TrimPrefix(plain.URL, "http://127.0.0.1:")

	stdout := captureStdio(t, "127.0.0.1\n", func() {
		runLegacy(8, 2*time.Second, "GET", false,
			[]string{"not-a-proto-port", fmt.Sprintf("http:%s", port)}, true)
	})
	if strings.TrimSpace(stdout) != fmt.Sprintf("http://127.0.0.1:%s", port) {
		t.Fatalf("legacy stdout = %q", stdout)
	}
}

func readDiag(t *testing.T, path string) []*Verdict {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []*Verdict
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		var v Verdict
		if err := json.Unmarshal(sc.Bytes(), &v); err != nil {
			t.Fatalf("diag line not JSON: %v (%q)", err, sc.Text())
		}
		out = append(out, &v)
	}
	return out
}
