package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type proxyMode int

const (
	proxyForward proxyMode = iota
	proxyAuthRequired
	proxyBadGateway
	proxySlow
)

type localProxy struct {
	server *httptest.Server

	mu      sync.Mutex
	hosts   []string
	methods []string
}

func startProxy(t *testing.T, mode proxyMode, username, password string) *localProxy {
	t.Helper()

	proxy := &localProxy{}
	expectedAuth := ""
	if username != "" || password != "" {
		expectedAuth = "Basic " + base64.StdEncoding.EncodeToString([]byte(username+":"+password))
	}

	proxy.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxy.mu.Lock()
		proxy.hosts = append(proxy.hosts, r.Host)
		proxy.methods = append(proxy.methods, r.Method)
		proxy.mu.Unlock()

		if expectedAuth != "" && r.Header.Get("Proxy-Authorization") != expectedAuth {
			w.Header().Set("Proxy-Authenticate", `Basic realm="test"`)
			w.WriteHeader(http.StatusProxyAuthRequired)
			return
		}

		switch mode {
		case proxyAuthRequired:
			w.Header().Set("Proxy-Authenticate", `Basic realm="test"`)
			w.WriteHeader(http.StatusProxyAuthRequired)
			return
		case proxyBadGateway:
			w.WriteHeader(http.StatusBadGateway)
			return
		case proxySlow:
			time.Sleep(300 * time.Millisecond)
			w.WriteHeader(http.StatusOK)
			return
		}

		if r.Method != http.MethodConnect {
			w.WriteHeader(http.StatusOK)
			return
		}

		upstream, err := net.DialTimeout("tcp", r.Host, time.Second)
		if err != nil {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			upstream.Close()
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		clientConn, _, err := hijacker.Hijack()
		if err != nil {
			upstream.Close()
			return
		}
		if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
			clientConn.Close()
			upstream.Close()
			return
		}
		go func() {
			io.Copy(upstream, clientConn)
			upstream.Close()
		}()
		go func() {
			io.Copy(clientConn, upstream)
			clientConn.Close()
		}()
	}))

	t.Cleanup(proxy.server.Close)
	return proxy
}

func (p *localProxy) address() string {
	return p.server.URL
}

func (p *localProxy) seenHosts() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.hosts...)
}

func runProbe(t *testing.T, input string, args ...string) (string, string, error) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	err := run(args, strings.NewReader(input), &stdout, &stderr)
	return stdout.String(), stderr.String(), err
}

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "httprobe.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func mustPort(t *testing.T, rawURL string) string {
	t.Helper()
	parsed, err := neturl(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func neturl(rawURL string) (string, error) {
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return "", err
	}
	return req.URL.Port(), nil
}

func TestSingleProxyHandlesHTTPHTTPSAndKeepsHostnameForProxy(t *testing.T) {
	proxy := startProxy(t, proxyForward, "", "")

	stdout, stderr, err := runProbe(t, "unresolved.invalid\n",
		"-proxy", proxy.address(),
		"-s", "-p", "http:8123",
	)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout, "http://unresolved.invalid:8123\tproxy=P0\trule=DEFAULT") {
		t.Fatalf("unexpected stdout: %q", stdout)
	}
	if strings.Contains(stderr, "FAIL\t") {
		t.Fatalf("unexpected failure: %q", stderr)
	}
	found := false
	for _, host := range proxy.seenHosts() {
		if host == "unresolved.invalid:8123" {
			found = true
		}
	}
	if !found {
		t.Fatalf("proxy did not receive original hostname: %v", proxy.seenHosts())
	}

	tlsTarget := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer tlsTarget.Close()
	tlsPort := mustPort(t, tlsTarget.URL)

	stdout, stderr, err = runProbe(t, "127.0.0.1\n",
		"-proxy", proxy.address(),
		"-s", "-p", "https:"+tlsPort, "--prefer-https",
	)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout, "https://127.0.0.1:"+tlsPort+"\tproxy=P0\trule=DEFAULT") {
		t.Fatalf("unexpected HTTPS stdout: %q", stdout)
	}
	if strings.Contains(stderr, "FAIL\t") {
		t.Fatalf("unexpected HTTPS failure: %q", stderr)
	}
}

func TestCIDRRoutingUsesLongestPrefixAndDirectFallback(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()
	targetPort := mustPort(t, target.URL)

	proxy0 := startProxy(t, proxyForward, "", "")
	proxy1 := startProxy(t, proxyForward, "", "")
	configPath := writeConfig(t, fmt.Sprintf(`{
		"targets": [
			"127.0.0.1",
			"10.2.3.4",
			"10.1.2.3"
		],
		"proxies": [
			{"id": "P0", "address": %q},
			{"id": "P1", "address": %q}
		],
		"rules": [
			{"id": "R0", "cidr": "10.0.0.0/8", "proxy_id": "P0"},
			{"id": "R1", "cidr": "10.1.0.0/16", "proxy_id": "P1"}
		]
	}`, proxy0.address(), proxy1.address()))

	stdout, stderr, err := runProbe(t, "", "-config", configPath, "-s", "-p", "http:"+targetPort)
	if err != nil {
		t.Fatal(err)
	}

	expected := []string{
		"http://127.0.0.1:" + targetPort + "\tproxy=direct\trule=DIRECT",
		"http://10.2.3.4:" + targetPort + "\tproxy=P0\trule=R0",
		"http://10.1.2.3:" + targetPort + "\tproxy=P1\trule=R1",
	}
	for _, line := range expected {
		if !strings.Contains(stdout, line) {
			t.Errorf("stdout missing %q:\n%s", line, stdout)
		}
	}
	if !strings.Contains(stderr, "SUMMARY\trule=R0\tcidr=10.0.0.0/8\tproxy=P0") {
		t.Errorf("missing R0 summary: %s", stderr)
	}
	if !strings.Contains(stderr, "SUMMARY\trule=R1\tcidr=10.1.0.0/16\tproxy=P1") {
		t.Errorf("missing R1 summary: %s", stderr)
	}
}

func TestConfigImportsTargetWithRuleAndUsesEnvironmentAuth(t *testing.T) {
	const (
		user     = "probe-user"
		password = "probe-password"
	)
	t.Setenv("TEST_PROXY_USER", user)
	t.Setenv("TEST_PROXY_PASSWORD", password)

	proxy := startProxy(t, proxyForward, user, password)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()
	targetPort := mustPort(t, target.URL)

	configPath := writeConfig(t, fmt.Sprintf(`{
		"targets": [{"host": "internal.invalid", "rule": "R0"}],
		"proxies": [{
			"id": "AUTH",
			"address": %q,
			"username_env": "TEST_PROXY_USER",
			"password_env": "TEST_PROXY_PASSWORD"
		}],
		"rules": [{"id": "R0", "cidr": "10.0.0.0/8", "proxy_id": "AUTH"}]
	}`, proxy.address()))

	stdout, stderr, err := runProbe(t, "", "-config", configPath, "-s", "-p", "http:"+targetPort)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout, "http://internal.invalid:"+targetPort+"\tproxy=AUTH\trule=R0") {
		t.Fatalf("unexpected stdout: %q", stdout)
	}
	if strings.Contains(stderr, "FAIL\t") {
		t.Fatalf("unexpected failure: %q", stderr)
	}

	tlsTarget := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer tlsTarget.Close()
	tlsPort := mustPort(t, tlsTarget.URL)
	httpsConfigPath := writeConfig(t, fmt.Sprintf(`{
		"targets": [{"host": "127.0.0.1", "rule": "R0"}],
		"proxies": [{
			"id": "AUTH",
			"address": %q,
			"username_env": "TEST_PROXY_USER",
			"password_env": "TEST_PROXY_PASSWORD"
		}],
		"rules": [{"id": "R0", "cidr": "127.0.0.0/8", "proxy_id": "AUTH"}]
	}`, proxy.address()))

	stdout, stderr, err = runProbe(t, "", "-config", httpsConfigPath, "-s", "-p", "https:"+tlsPort, "--prefer-https")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout, "https://127.0.0.1:"+tlsPort+"\tproxy=AUTH\trule=R0") {
		t.Fatalf("unexpected HTTPS stdout with auth: %q", stdout)
	}
	if strings.Contains(stderr, "FAIL\t") {
		t.Fatalf("unexpected HTTPS auth failure: %q", stderr)
	}
}

func TestProxyFailureTypesAreDistinct(t *testing.T) {
	closedListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	refusedAddress := closedListener.Addr().String()
	closedListener.Close()

	authProxy := startProxy(t, proxyAuthRequired, "", "")
	badGatewayProxy := startProxy(t, proxyBadGateway, "", "")
	tlsTarget := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer tlsTarget.Close()
	tlsPort := mustPort(t, tlsTarget.URL)

	normalProxy := startProxy(t, proxyForward, "", "")
	targetListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedTarget := targetListener.Addr().String()
	targetListener.Close()
	directConfig := writeConfig(t, fmt.Sprintf(`{
		"proxies": [{"id": "P0", "address": %q}],
		"rules": [{"id": "R0", "cidr": "10.0.0.0/8", "proxy_id": "P0"}]
	}`, normalProxy.address()))

	tests := []struct {
		name string
		args []string
		in   string
		code string
	}{
		{
			name: "proxy connection refused",
			args: []string{"-proxy", "http://" + refusedAddress, "-s", "-p", "http:80"},
			in:   "target.invalid\n",
			code: codeProxyConnectRefused,
		},
		{
			name: "proxy 407",
			args: []string{"-proxy", authProxy.address(), "-s", "-p", "http:80"},
			in:   "target.invalid\n",
			code: codeProxyAuthRequired,
		},
		{
			name: "proxy 502",
			args: []string{"-proxy", badGatewayProxy.address(), "-s", "-p", "http:80"},
			in:   "target.invalid\n",
			code: codeProxyBadGateway,
		},
		{
			name: "HTTPS proxy 407",
			args: []string{"-proxy", authProxy.address(), "-s", "-p", "https:" + tlsPort, "--prefer-https"},
			in:   "127.0.0.1\n",
			code: codeProxyAuthRequired,
		},
		{
			name: "HTTPS proxy 502 keeps target hostname",
			args: []string{"-proxy", badGatewayProxy.address(), "-s", "-p", "https:443", "--prefer-https"},
			in:   "unresolved.invalid\n",
			code: codeProxyBadGateway,
		},
		{
			name: "target connection refused",
			args: []string{"-config", directConfig, "-s", "-p", "http:" + mustPortFromHostPort(t, closedTarget)},
			in:   "127.0.0.1\n",
			code: codeTargetConnectRefused,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, stderr, err := runProbe(t, test.in, test.args...)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(stderr, "code="+test.code) {
				t.Fatalf("stderr missing %s:\n%s", test.code, stderr)
			}
			t.Logf("actual stderr for %s:\n%s", test.code, stderr)
		})
	}

	found := false
	for _, host := range badGatewayProxy.seenHosts() {
		if host == "unresolved.invalid:443" {
			found = true
		}
	}
	if !found {
		t.Fatalf("proxy did not receive CONNECT hostname: %v", badGatewayProxy.seenHosts())
	}
}

func mustPortFromHostPort(t *testing.T, hostport string) string {
	t.Helper()
	_, port, err := net.SplitHostPort(hostport)
	if err != nil {
		t.Fatal(err)
	}
	return port
}

func TestCircuitBreakerFastFailsAfterThreshold(t *testing.T) {
	proxy := startProxy(t, proxyBadGateway, "", "")
	_, stderr, err := runProbe(t, "a.invalid\nb.invalid\nc.invalid\nd.invalid\ne.invalid\n",
		"-proxy", proxy.address(),
		"-proxy-fail-threshold", "1",
		"-c", "2",
		"-s", "-p", "http:80",
	)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stderr, "code="+codeProxyCircuitOpen) {
		t.Fatalf("expected circuit-open fast failures:\n%s", stderr)
	}
	if !strings.Contains(stderr, "circuit_open=") {
		t.Fatalf("expected circuit stats:\n%s", stderr)
	}
}

func TestReadTimeoutIsDistinctFromConnectionTimeout(t *testing.T) {
	proxy := startProxy(t, proxySlow, "", "")
	_, stderr, err := runProbe(t, "slow.invalid\n",
		"-proxy", proxy.address(),
		"-t", "1000",
		"-read-timeout", "50",
		"-c", "2",
		"-s", "-p", "http:80",
	)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stderr, "code="+codeProxyReadTimeout) {
		t.Fatalf("expected read timeout:\n%s", stderr)
	}
}

type testTimeoutError struct{}

func (testTimeoutError) Error() string   { return "test timeout" }
func (testTimeoutError) Timeout() bool   { return true }
func (testTimeoutError) Temporary() bool { return true }

func TestConnectionAndReadTimeoutsUseDistinctCodes(t *testing.T) {
	timeoutErr := &net.OpError{Op: "dial", Net: "tcp", Err: testTimeoutError{}}

	direct := classifyError(timeoutErr, &route{})
	if direct.code != codeTargetTimeout {
		t.Fatalf("direct timeout code = %s, want %s", direct.code, codeTargetTimeout)
	}

	proxied := classifyError(timeoutErr, &route{proxy: &proxyEndpoint{}})
	if proxied.code != codeProxyConnectTimeout {
		t.Fatalf("proxy connect timeout code = %s, want %s", proxied.code, codeProxyConnectTimeout)
	}
}

func TestNoProxyOutputIsUnchanged(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()
	targetPort := mustPort(t, target.URL)

	stdout, stderr, err := runProbe(t, "127.0.0.1\n", "-s", "-p", "http:"+targetPort)
	if err != nil {
		t.Fatal(err)
	}
	want := "http://127.0.0.1:" + targetPort + "\n"
	if stdout != want {
		t.Fatalf("stdout changed: got %q want %q", stdout, want)
	}
	if stderr != "" {
		t.Fatalf("unexpected stderr: %q", stderr)
	}
}

func TestConfigValidationFailsAtStartup(t *testing.T) {
	t.Run("bad proxy address names rule", func(t *testing.T) {
		configPath := writeConfig(t, `{
			"proxies": [{"id": "P0", "address": "127.0.0.1"}],
			"rules": [{"id": "R7", "cidr": "10.0.0.0/8", "proxy_id": "P0"}]
		}`)
		_, _, err := runProbe(t, "", "-config", configPath, "-s")
		if err == nil || !strings.Contains(err.Error(), "rule") || !strings.Contains(err.Error(), "R7") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("plaintext password is rejected", func(t *testing.T) {
		configPath := writeConfig(t, `{
			"proxies": [{"id": "P0", "address": "http://127.0.0.1:8080", "password": "secret"}]
		}`)
		_, _, err := runProbe(t, "", "-config", configPath, "-s")
		if err == nil || !strings.Contains(err.Error(), "unknown field") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("proxy URL credentials are rejected", func(t *testing.T) {
		_, _, err := runProbe(t, "", "-proxy", "http://user:pass@127.0.0.1:8080", "-s")
		if err == nil || !strings.Contains(err.Error(), "credentials") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("same-prefix overlap is rejected", func(t *testing.T) {
		configPath := writeConfig(t, `{
			"rules": [
				{"id": "R0", "cidr": "10.0.0.0/8"},
				{"id": "R1", "cidr": "10.0.0.0/8"}
			]
		}`)
		_, _, err := runProbe(t, "", "-config", configPath, "-s")
		if err == nil || !strings.Contains(err.Error(), "overlap") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("missing auth environment is rejected", func(t *testing.T) {
		configPath := writeConfig(t, `{
			"proxies": [{
				"id": "P0",
				"address": "http://127.0.0.1:8080",
				"username_env": "MISSING_PROXY_USER_63",
				"password_env": "MISSING_PROXY_PASSWORD_63"
			}]
		}`)
		_, _, err := runProbe(t, "", "-config", configPath, "-s")
		if err == nil || !strings.Contains(err.Error(), "MISSING_PROXY_USER_63") {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}
