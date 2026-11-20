package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strings"
	"syscall"
	"time"
)

// Category is the machine-readable outcome of a probe.
type Category string

const (
	// CategoryAvailable means a complete HTTP response was received.
	CategoryAvailable Category = "available"

	// CategoryConnectTimeout: no response to the connection handshake,
	// the connect-phase budget was exhausted.
	CategoryConnectTimeout Category = "connect_timeout"

	// CategoryReadTimeout: the connection was established, but no complete
	// response (TLS handshake or HTTP response headers) arrived before the
	// read-phase budget was exhausted.
	CategoryReadTimeout Category = "read_timeout"

	// CategoryTLSProtocol: the port was reachable but the TLS handshake was
	// rejected by the peer (protocol version / cipher-suite mismatch, etc.).
	CategoryTLSProtocol Category = "tls_protocol"

	// CategoryTLSCertificate: the TLS handshake completed but certificate
	// chain verification failed.
	CategoryTLSCertificate Category = "tls_certificate"

	// CategoryConnectionRefused: the peer explicitly rejected the connection.
	// Deterministic; never retried.
	CategoryConnectionRefused Category = "connection_refused"

	// CategoryDNSError: name resolution failed. This is a local-side problem
	// and must not be presented as remote unreachability.
	CategoryDNSError Category = "dns_error"

	// CategoryUnknown: no observable signal matched a known class
	// (e.g. the peer disconnects mid-negotiation). The raw error text is
	// retained for manual triage.
	CategoryUnknown Category = "unknown"
)

// retryableCategories are the only categories a retry may be attempted for.
// Everything else is a deterministic verdict.
var retryableCategories = map[Category]bool{
	CategoryConnectTimeout: true,
	CategoryReadTimeout:    true,
}

// Verdict is the final, de-duplicated conclusion for one target URL.
type Verdict struct {
	Target   string   `json:"target"`
	Category Category `json:"category"`
	// Retries is the number of *re-attempts* performed after the first try.
	Retries int    `json:"retries"`
	Err     string `json:"error,omitempty"`
}

func (v *Verdict) available() bool {
	return v.Category == CategoryAvailable
}

// Prober runs probes against individual target URLs.
//
// Time budgets (hard constraints):
//   - connectPhaseTimeout is the independent budget for establishing the
//     TCP connection (including name resolution).
//   - readPhaseTimeout is the independent budget for everything after the
//     connection is accepted: TLS handshake and reading the response headers.
//   - overallDeadline bounds the total wall-clock time spent on one target,
//     including retries, so retries can never multiply the budget.
type Prober struct {
	connectPhaseTimeout time.Duration
	readPhaseTimeout    time.Duration
	overallDeadline     time.Duration
	maxRetries          int
	method              string
	// verifyCerts enables certificate-chain verification. When false the
	// legacy behavior (InsecureSkipVerify) is preserved.
	verifyCerts bool
	// tlsMinVersion, when non-zero, overrides the client's minimum TLS
	// version. Test-only hook for exercising protocol negotiation failures.
	tlsMinVersion uint16
}

// Probe runs the full retry loop for a single target URL and returns the
// final verdict. Retries happen only for retryable categories; deterministic
// verdicts are returned immediately. The verdict category is always the
// category of the last attempt, so a deterministic conclusion can never be
// turned into "unknown" by retrying.
func (p *Prober) Probe(ctx context.Context, rawURL string) *Verdict {
	deadline := time.Now().Add(p.overallDeadline)

	var lastErr string
	attempts := 0

	for {
		cat, err := p.probeOnce(ctx, rawURL, deadline)
		attempts++
		if err != nil {
			lastErr = err.Error()
		} else {
			lastErr = ""
		}

		if cat == CategoryAvailable {
			return &Verdict{Target: rawURL, Category: CategoryAvailable, Retries: attempts - 1}
		}

		// Only the two budget-exhaustion classes are retryable.
		if !retryableCategories[cat] {
			return &Verdict{Target: rawURL, Category: cat, Retries: attempts - 1, Err: lastErr}
		}

		if attempts-1 >= p.maxRetries || time.Until(deadline) <= 0 {
			return &Verdict{Target: rawURL, Category: cat, Retries: attempts - 1, Err: lastErr}
		}
	}
}

// probeOnce performs a single attempt. The overall deadline is passed in so
// an attempt can never outlive the per-target total budget.
func (p *Prober) probeOnce(parent context.Context, rawURL string, overallDeadline time.Time) (Category, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		// Malformed input: deterministic local-side problem, nothing to probe.
		return CategoryUnknown, err
	}
	isTLS := parsed.Scheme == "https"
	host := parsed.Hostname()
	port := parsed.Port()
	if port == "" {
		if isTLS {
			port = "443"
		} else {
			port = "80"
		}
	}
	serverName := host

	// Phase 1: name resolution + TCP connect, with its own independent
	// budget, clamped to the overall per-target deadline so a retry can never
	// push total wall-clock time past the absolute cap.
	connectBudget := p.connectPhaseTimeout
	if remaining := time.Until(overallDeadline); remaining < connectBudget {
		connectBudget = remaining
	}
	if connectBudget <= 0 {
		return CategoryConnectTimeout, context.DeadlineExceeded
	}
	connectCtx, connectCancel := context.WithTimeout(parent, connectBudget)
	defer connectCancel()

	dialer := &net.Dialer{Timeout: connectBudget, KeepAlive: time.Second}
	conn, err := dialer.DialContext(connectCtx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return classifyDialError(err), err
	}
	defer conn.Close()

	// Phase 2: everything post-connect (TLS handshake + HTTP response
	// headers) shares the independent read-phase budget.
	if isTLS {
		tlsCfg := &tls.Config{ServerName: serverName}
		if p.tlsMinVersion != 0 {
			tlsCfg.MinVersion = p.tlsMinVersion
		}
		if !p.verifyCerts {
			tlsCfg.InsecureSkipVerify = true
		}
		tlsConn := tls.Client(conn, tlsCfg)
		// Cap the handshake at the earlier of the read-phase budget and the
		// overall per-target deadline.
		handshakeDeadline := time.Now().Add(p.readPhaseTimeout)
		if overallDeadline.Before(handshakeDeadline) {
			handshakeDeadline = overallDeadline
		}
		if err := tlsConn.SetDeadline(handshakeDeadline); err != nil {
			return CategoryUnknown, err
		}
		if err := tlsConn.HandshakeContext(parent); err != nil {
			return classifyTLSError(err), err
		}
		// Handshake done; reset the deadline for the HTTP portion of the
		// read-phase budget.
		readDeadline := time.Now().Add(p.readPhaseTimeout)
		if overallDeadline.Before(readDeadline) {
			readDeadline = overallDeadline
		}
		if err := tlsConn.SetDeadline(readDeadline); err != nil {
			return CategoryUnknown, err
		}
		conn = tlsConn
	} else {
		readDeadline := time.Now().Add(p.readPhaseTimeout)
		if overallDeadline.Before(readDeadline) {
			readDeadline = overallDeadline
		}
		if err := conn.SetDeadline(readDeadline); err != nil {
			return CategoryUnknown, err
		}
	}

	// Issue the HTTP request and read the response headers.
	req, err := http.NewRequestWithContext(parent, p.method, rawURL, nil)
	if err != nil {
		return CategoryUnknown, err
	}
	req.Header.Add("Connection", "close")
	req.Close = true
	req.RequestURI = ""

	if err := req.Write(conn); err != nil {
		return classifyPostConnectError(err), err
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		return classifyReadError(err), err
	}
	io.Copy(ioutil.Discard, resp.Body)
	resp.Body.Close()

	// Any parseable HTTP response means the service is usable — matching the
	// legacy isListening semantics (status code is irrelevant).
	return CategoryAvailable, nil
}

// classifyDialError maps failures observed before a connection is established.
func classifyDialError(err error) Category {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		// A DNS lookup that itself times out is still a local-side problem.
		return CategoryDNSError
	}
	if isTimeout(err) {
		return CategoryConnectTimeout
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return CategoryConnectionRefused
	}
	return CategoryUnknown
}

// classifyTLSError maps failures observed during the TLS handshake.
func classifyTLSError(err error) Category {
	// Certificate-chain verification failure — the negotiation itself
	// completed, so this must never be merged with tls_protocol.
	var certVerifyErr *tls.CertificateVerificationError
	if errors.As(err, &certVerifyErr) {
		return CategoryTLSCertificate
	}
	var unknownAuth x509.UnknownAuthorityError
	if errors.As(err, &unknownAuth) {
		return CategoryTLSCertificate
	}
	var hostNameErr x509.HostnameError
	if errors.As(err, &hostNameErr) {
		return CategoryTLSCertificate
	}

	if isTimeout(err) {
		return CategoryReadTimeout
	}

	// Explicit TLS alerts from the peer are deterministic negotiation
	// rejections (protocol version, cipher suite, handshake failure, ...).
	var alertErr tls.AlertError
	if errors.As(err, &alertErr) {
		return CategoryTLSProtocol
	}
	// In current Go versions alert errors are wrapped as *tls.permanentError,
	// whose Error() text is stable and always starts with "remote error: tls:".
	// The match is on the documented peer-signal prefix, not on timing.
	if strings.HasPrefix(err.Error(), "remote error: tls:") {
		return CategoryTLSProtocol
	}

	return CategoryUnknown
}

// classifyReadError maps failures while reading the HTTP response headers.
func classifyReadError(err error) Category {
	if isTimeout(err) {
		return CategoryReadTimeout
	}
	// EOF / reset / closed-without-response after connect: unclassifiable
	// without further signals; keep the raw text for manual triage.
	return CategoryUnknown
}

// classifyPostConnectError maps failures while writing the HTTP request.
func classifyPostConnectError(err error) Category {
	if isTimeout(err) {
		return CategoryReadTimeout
	}
	return CategoryUnknown
}

func isTimeout(err error) bool {
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	return errors.Is(err, context.DeadlineExceeded)
}

// String exists only to keep category rendering explicit in ad-hoc tooling.
func (c Category) String() string { return string(c) }
