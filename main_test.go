package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

func localServers(t *testing.T) (string, string) {
	t.Helper()

	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(httpServer.Close)

	httpsServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(httpsServer.Close)

	return strings.TrimPrefix(httpServer.URL, "http://"), strings.TrimPrefix(httpsServer.URL, "https://")
}

func hostOf(target string) string {
	index := strings.LastIndex(target, ":")
	return target[:index]
}

func dualProtocolTarget(t *testing.T) string {
	t.Helper()

	baseListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	certificate, err := tls.LoadX509KeyPair(filepath.Join("testdata", "test-cert.pem"), filepath.Join("testdata", "test-key.pem"))
	if err != nil {
		t.Fatalf("load test certificate: %v", err)
	}

	listener := &splitListener{
		Listener: baseListener,
		tlsConfig: &tls.Config{
			Certificates: []tls.Certificate{certificate},
		},
	}

	server := &http.Server{Handler: handler}
	go func() {
		_ = server.Serve(listener)
	}()

	t.Cleanup(func() {
		server.Close()
	})

	return baseListener.Addr().String()
}

type splitListener struct {
	net.Listener
	tlsConfig *tls.Config
}

func (l *splitListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	firstByte := make([]byte, 1)
	if _, err := conn.Read(firstByte); err != nil {
		conn.Close()
		return nil, err
	}

	peeked := &peekConn{Conn: conn, peek: firstByte}
	if firstByte[0] == 0x16 {
		return tls.Server(peeked, l.tlsConfig), nil
	}
	return peeked, nil
}

type peekConn struct {
	net.Conn
	peek []byte
}

func (c *peekConn) Read(buffer []byte) (int, error) {
	if len(c.peek) > 0 {
		n := copy(buffer, c.peek)
		c.peek = c.peek[n:]
		return n, nil
	}
	return c.Conn.Read(buffer)
}

func readSARIF(t *testing.T, path string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read SARIF output: %v", err)
	}
	var document map[string]any
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatalf("decode SARIF output: %v", err)
	}
	return document
}

func resultCount(t *testing.T, document any) int {
	t.Helper()
	return len(document.(map[string]any)["runs"].([]any)[0].(map[string]any)["results"].([]any))
}

func TestExecuteProducesSeparateHTTPAndHTTPSResults(t *testing.T) {
	target := dualProtocolTarget(t)

	var stdout, stderr bytes.Buffer
	outputPath := filepath.Join(t.TempDir(), "multi.sarif")
	opts := runOptions{
		concurrency: 4,
		skipDefault: true,
		probes:      []string{"https:" + portOf(target), "http:" + portOf(target)},
		timeout:     time.Second,
		method:      "GET",
		input:       strings.NewReader(hostOf(target) + "\n"),
		output:      &stdout,
		sarifFile:   outputPath,
		repoRoot:    t.TempDir(),
		flushEvery:  1,
	}

	if code := execute(opts, &stderr); code != 0 {
		t.Fatalf("execute returned code %d, stderr: %s", code, stderr.String())
	}

	document := validateSARIFDocument(t, outputPath)
	run := document.(map[string]any)["runs"].([]any)[0].(map[string]any)
	results := run["results"].([]any)
	protocols := map[string]bool{}
	for _, rawResult := range results {
		result := rawResult.(map[string]any)
		protocol := result["properties"].(map[string]any)["protocol"].(string)
		protocols[protocol] = true
		region := result["locations"].([]any)[0].(map[string]any)["physicalLocation"].(map[string]any)["region"].(map[string]any)
		if region["startLine"].(float64) != 1 {
			t.Fatalf("expected startLine 1, got %v", region["startLine"])
		}
		if result["message"].(map[string]any)["text"].(string) == "" {
			t.Fatalf("result is missing a message")
		}
	}
	if !protocols["http"] || !protocols["https"] {
		t.Fatalf("expected distinct http and https results, got %v", protocols)
	}
	for _, rawResult := range results {
		result := rawResult.(map[string]any)
		if result["level"].(string) != severityToLevel[severityHigh] {
			t.Fatalf("non-standard port finding must map to error, got %q", result["level"])
		}
	}
	printed := strings.Split(strings.TrimSpace(stdout.String()), "\n")
	sort.Strings(printed)
	if len(printed) != len(results) {
		t.Fatalf("expected one stdout line per SARIF result, got %d lines and %d results", len(printed), len(results))
	}
	if !strings.HasPrefix(printed[0], "http://127.0.0.1:") || !strings.Contains(printed[len(printed)-1], "https://127.0.0.1:") {
		t.Fatalf("stdout no longer prints one URL per line: %q", stdout.String())
	}
}

func TestExecuteSameRuleMultipleSitesPerLine(t *testing.T) {
	target := dualProtocolTarget(t)

	var stdout, stderr bytes.Buffer
	outputPath := filepath.Join(t.TempDir(), "sites.sarif")
	opts := runOptions{
		concurrency: 2,
		skipDefault: true,
		probes:      []string{"http:" + portOf(target)},
		timeout:     time.Second,
		method:      "GET",
		input:       strings.NewReader(hostOf(target) + "\n" + hostOf(target) + "\n" + hostOf(target) + "\n"),
		output:      &stdout,
		sarifFile:   outputPath,
		repoRoot:    t.TempDir(),
		flushEvery:  1,
	}

	if code := execute(opts, &stderr); code != 0 {
		t.Fatalf("execute returned code %d, stderr: %s", code, stderr.String())
	}

	document := validateSARIFDocument(t, outputPath)
	results := document.(map[string]any)["runs"].([]any)[0].(map[string]any)["results"].([]any)
	if len(results) != 3 {
		t.Fatalf("each of the three input lines must expand to its own result, got %d", len(results))
	}

	seenLines := map[float64]int{}
	for _, rawResult := range results {
		result := rawResult.(map[string]any)
		if result["ruleId"].(string) != ruleNonStdPort {
			t.Fatalf("expected the same rule ID for every site, got %q", result["ruleId"])
		}
		region := result["locations"].([]any)[0].(map[string]any)["physicalLocation"].(map[string]any)["region"].(map[string]any)
		seenLines[region["startLine"].(float64)]++
		if region["startColumn"].(float64) != 1 || region["endColumn"].(float64) != float64(utf16Length(hostOf(target))+1) {
			t.Fatalf("unexpected column span for line %v: %v", region["startLine"], region)
		}
	}
	for line := float64(1); line <= 3; line++ {
		if seenLines[line] != 1 {
			t.Fatalf("expected exactly one result on line %v, got %d", line, seenLines[line])
		}
	}
}

func TestExecuteZeroHitsWritesValidEmptySARIF(t *testing.T) {
	var stdout, stderr bytes.Buffer
	outputPath := filepath.Join(t.TempDir(), "zero.sarif")
	opts := runOptions{
		concurrency: 2,
		skipDefault: true,
		probes:      []string{"http:1"},
		timeout:     100 * time.Millisecond,
		method:      "GET",
		input:       strings.NewReader("127.0.0.1\n"),
		output:      &stdout,
		sarifFile:   outputPath,
		repoRoot:    t.TempDir(),
		flushEvery:  sarifFlushEvery,
	}

	if code := execute(opts, &stderr); code != 0 {
		t.Fatalf("execute returned code %d, stderr: %s", code, stderr.String())
	}

	document := validateSARIFDocument(t, outputPath)
	if resultCount(t, document) != 0 {
		t.Fatalf("expected zero results, got %d", resultCount(t, document))
	}
	if stdout.Len() != 0 {
		t.Fatalf("zero-hit scan must not print URLs, got %q", stdout.String())
	}
}

func TestExecuteMidScanFailureMarksInvocation(t *testing.T) {
	httpTarget, _ := localServers(t)

	var stdout, stderr bytes.Buffer
	outputPath := filepath.Join(t.TempDir(), "failure.sarif")
	opts := runOptions{
		concurrency: 2,
		skipDefault: true,
		probes:      []string{"http:" + portOf(httpTarget)},
		timeout:     time.Second,
		method:      "GET",
		input:       strings.NewReader(hostOf(httpTarget) + "\n127.0.0.1\n127.0.0.1\n"),
		output:      &stdout,
		sarifFile:   outputPath,
		repoRoot:    t.TempDir(),
		flushEvery:  sarifFlushEvery,
		failAfter:   1,
	}

	if code := execute(opts, &stderr); code != 0 {
		t.Fatalf("failure injection must not change the exit code, got %d", code)
	}

	document := validateSARIFDocument(t, outputPath)
	invocation := document.(map[string]any)["runs"].([]any)[0].(map[string]any)["invocations"].([]any)[0].(map[string]any)
	if invocation["executionSuccessful"] != false {
		t.Fatalf("expected a failed invocation marker, got %v", invocation)
	}
	if len(invocation["toolExecutionNotifications"].([]any)) != 1 {
		t.Fatalf("expected one error notification, got %v", invocation)
	}
}

func TestDefaultPathWithoutSARIFIsByteIdentical(t *testing.T) {
	target := dualProtocolTarget(t)
	input := hostOf(target) + "\n"

	var plainOut, plainErr bytes.Buffer
	plain := runOptions{
		concurrency: 4,
		skipDefault: true,
		probes:      []string{"http:" + portOf(target), "https:" + portOf(target)},
		timeout:     time.Second,
		method:      "GET",
		input:       strings.NewReader(input),
		output:      &plainOut,
		flushEvery:  sarifFlushEvery,
	}
	if code := execute(plain, &plainErr); code != 0 {
		t.Fatalf("baseline execute failed: %s", plainErr.String())
	}

	var sarifOut, sarifErr bytes.Buffer
	sarifOpts := plain
	sarifOpts.input = strings.NewReader(input)
	sarifOpts.output = &sarifOut
	sarifOpts.sarifFile = filepath.Join(t.TempDir(), "side-effect.sarif")
	sarifOpts.repoRoot = t.TempDir()
	if code := execute(sarifOpts, &sarifErr); code != 0 {
		t.Fatalf("sarif execute failed: %s", sarifErr.String())
	}

	baselineLines := sortedLines(plainOut.String())
	sarifLines := sortedLines(sarifOut.String())
	if strings.Join(baselineLines, "\n") != strings.Join(sarifLines, "\n") {
		t.Fatalf("stdout line set changed when SARIF was enabled:\nbaseline=%q\nsarif=%q", plainOut.String(), sarifOut.String())
	}
	if plainErr.Len() != sarifErr.Len() {
		t.Fatalf("stderr changed when SARIF was enabled:\nbaseline=%q\nsarif=%q", plainErr.String(), sarifErr.String())
	}

	expectedLines := []string{"http://" + target, "http://" + target, "https://" + target}
	sort.Strings(expectedLines)
	if strings.Join(baselineLines, "\n") != strings.Join(expectedLines, "\n") {
		t.Fatalf("default stdout content changed: %q", plainOut.String())
	}

	// Every emitted line must remain exactly scheme://host:port plus a
	// trailing newline, i.e. byte-identical to the legacy fmt.Println output.
	for _, line := range baselineLines {
		if !strings.HasSuffix(plainOut.String(), "\n") {
			t.Fatalf("legacy stdout must remain newline terminated")
		}
		if strings.Contains(line, " ") {
			t.Fatalf("legacy stdout line format changed: %q", line)
		}
	}
}

func sortedLines(output string) []string {
	lines := strings.Split(strings.TrimSpace(output), "\n")
	sort.Strings(lines)
	return lines
}

func TestExecuteUsesRelativeLocationForInputFile(t *testing.T) {
	httpTarget, _ := localServers(t)
	repoRoot := t.TempDir()
	inputDir := filepath.Join(repoRoot, "recon")
	if err := os.MkdirAll(inputDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	linkPath := filepath.Join(inputDir, "domains.txt")
	targetPath := filepath.Join(inputDir, "real-domains.txt")
	if err := os.WriteFile(targetPath, []byte(hostOf(httpTarget)+"\n"), 0o644); err != nil {
		t.Fatalf("write input: %v", err)
	}
	if err := os.Symlink(targetPath, linkPath); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	var stdout, stderr bytes.Buffer
	outputPath := filepath.Join(t.TempDir(), "input-file.sarif")
	opts := runOptions{
		concurrency: 2,
		skipDefault: true,
		probes:      []string{"http:" + portOf(httpTarget)},
		timeout:     time.Second,
		method:      "GET",
		output:      &stdout,
		sarifFile:   outputPath,
		inputFile:   linkPath,
		repoRoot:    repoRoot,
		flushEvery:  sarifFlushEvery,
	}

	if code := execute(opts, &stderr); code != 0 {
		t.Fatalf("execute returned code %d, stderr: %s", code, stderr.String())
	}

	document := validateSARIFDocument(t, outputPath)
	results := document.(map[string]any)["runs"].([]any)[0].(map[string]any)["results"].([]any)
	if len(results) != 1 {
		t.Fatalf("expected one result, got %d", len(results))
	}
	uri := results[0].(map[string]any)["locations"].([]any)[0].(map[string]any)["physicalLocation"].(map[string]any)["artifactLocation"].(map[string]any)["uri"].(string)
	if uri != "recon/domains.txt" {
		t.Fatalf("expected repo-relative symlink path, got %q", uri)
	}
}

func TestRunFlagParsingPreservesExitCodes(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run("httprobe", []string{"-h"}, strings.NewReader(""), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("help expected exit code 0, got %d", code)
	}

	stderr.Reset()
	code = run("httprobe", []string{"-unknown-flag"}, strings.NewReader(""), &stdout, &stderr)
	if code != 2 {
		t.Fatalf("bad flag expected exit code 2, got %d", code)
	}
	if !strings.Contains(stderr.String(), "flag provided but not defined") {
		t.Fatalf("flag error message changed: %q", stderr.String())
	}
}

func TestSARIFChunkedWriteDoesNotBufferEverything(t *testing.T) {
	httpTarget, _ := localServers(t)
	var stdout, stderr bytes.Buffer
	outputPath := filepath.Join(t.TempDir(), "chunks.sarif")

	opts := runOptions{
		concurrency: 8,
		skipDefault: true,
		probes:      []string{"http:" + portOf(httpTarget)},
		timeout:     time.Second,
		method:      "GET",
		output:      &stdout,
		sarifFile:   outputPath,
		repoRoot:    t.TempDir(),
		flushEvery:  250,
	}

	var input bytes.Buffer
	writer := bufio.NewWriter(&input)
	for index := 0; index < 1500; index++ {
		writer.WriteString(hostOf(httpTarget) + "\n")
	}
	writer.Flush()
	opts.input = &input

	if code := execute(opts, &stderr); code != 0 {
		t.Fatalf("execute returned code %d, stderr: %s", code, stderr.String())
	}

	document := validateSARIFDocument(t, outputPath)
	if resultCount(t, document) != 1500 {
		t.Fatalf("expected 1500 chunked results, got %d", resultCount(t, document))
	}
}

func portOf(target string) string {
	index := strings.LastIndex(target, ":")
	return target[index+1:]
}
