package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestNormalizeLine_Table(t *testing.T) {
	// Acceptance 五.1: prefix, port, path, whitespace, case and trailing-dot
	// spellings, each with an explicit assertion on the canonical result.
	tests := []struct {
		name       string
		line       string
		wantTarget string
		wantHost   string
		wantPort   string
		wantScheme string
		wantTail   string
		wantBlank  bool
		wantErr    string // substring expected in the invalid reason
	}{
		// --- protocol prefixes, mixed case ---
		{
			name:       "https prefix lowercase",
			line:       "https://example.com",
			wantTarget: "example.com", wantHost: "example.com",
			wantScheme: "https",
		},
		{
			name:       "HTTP prefix uppercase",
			line:       "HTTP://EXAMPLE.COM",
			wantTarget: "example.com", wantHost: "example.com",
			wantScheme: "HTTP",
		},
		{
			name:       "mixed case prefix and host",
			line:       "HtTpS://ExAmPlE.CoM",
			wantTarget: "example.com", wantHost: "example.com",
			wantScheme: "HtTpS",
		},
		{
			name:       "no prefix",
			line:       "example.com",
			wantTarget: "example.com", wantHost: "example.com",
		},

		// --- explicit non-default port ---
		{
			name:       "explicit port",
			line:       "example.com:8443",
			wantTarget: "example.com:8443", wantHost: "example.com", wantPort: "8443",
		},
		{
			name:       "explicit port with prefix and uppercase host",
			line:       "HTTPS://EXAMPLE.COM:8080",
			wantTarget: "example.com:8080", wantHost: "example.com", wantPort: "8080",
			wantScheme: "HTTPS",
		},
		{
			name:       "port with leading zeros canonicalized",
			line:       "example.com:0080",
			wantTarget: "example.com:80", wantHost: "example.com", wantPort: "80",
		},

		// --- path / query / fragment kept out of target, kept in trace ---
		{
			name:       "path stripped from target",
			line:       "https://example.com/admin/login",
			wantTarget: "example.com", wantHost: "example.com",
			wantScheme: "https", wantTail: "/admin/login",
		},
		{
			name:       "query and fragment stripped",
			line:       "example.com:8080/path?x=1#frag",
			wantTarget: "example.com:8080", wantHost: "example.com", wantPort: "8080",
			wantTail: "/path?x=1#frag",
		},
		{
			name:       "bare query",
			line:       "example.com?a=b",
			wantTarget: "example.com", wantHost: "example.com", wantTail: "?a=b",
		},

		// --- surrounding whitespace, tabs, CR, blank-only lines ---
		{
			name:       "leading and trailing spaces",
			line:       "  example.com  ",
			wantTarget: "example.com", wantHost: "example.com",
		},
		{
			name:       "tabs and carriage return",
			line:       "\thttps://example.com\r\n",
			wantTarget: "example.com", wantHost: "example.com", wantScheme: "https",
		},
		{
			name:      "blank line",
			line:      "",
			wantBlank: true,
		},
		{
			name:      "whitespace-only line",
			line:      "   \t\r\n  ",
			wantBlank: true,
		},

		// --- case and trailing dots ---
		{
			name:       "uppercase host",
			line:       "EXAMPLE.COM",
			wantTarget: "example.com", wantHost: "example.com",
		},
		{
			name:       "trailing dot",
			line:       "example.com.",
			wantTarget: "example.com", wantHost: "example.com",
		},
		{
			name:       "trailing dot with uppercase",
			line:       "EXAMPLE.COM.",
			wantTarget: "example.com", wantHost: "example.com",
		},
		{
			name:    "double trailing dot is invalid",
			line:    "example.com..",
			wantErr: "invalid host name",
		},

		// --- internationalized domain names ---
		{
			name:       "IDN converted to punycode, original kept in trace raw",
			line:       "bücher.example",
			wantTarget: "xn--bcher-kva.example",
			wantHost:   "xn--bcher-kva.example",
		},
		{
			name:       "IDN with prefix and path",
			line:       "https://bücher.example/katalog?q=1",
			wantTarget: "xn--bcher-kva.example",
			wantHost:   "xn--bcher-kva.example",
			wantScheme: "https", wantTail: "/katalog?q=1",
		},
		{
			name:    "IDN conversion failure preserved as invalid",
			line:    "xn--a.example", // malformed punycode label
			wantErr: "invalid or unconvertible host name",
		},

		// --- IPv6 literals ---
		{
			name:       "IPv6 unbracketed",
			line:       "2001:db8::1",
			wantTarget: "[2001:db8::1]", wantHost: "2001:db8::1",
		},
		{
			name:       "IPv6 bracketed",
			line:       "[2001:db8::1]",
			wantTarget: "[2001:db8::1]", wantHost: "2001:db8::1",
		},
		{
			name:       "IPv6 bracketed with port",
			line:       "[2001:db8::1]:8443",
			wantTarget: "[2001:db8::1]:8443", wantHost: "2001:db8::1", wantPort: "8443",
		},
		{
			name:       "full IPv6 canonicalized",
			line:       "[2001:0db8:0000:0000:0000:0000:0000:0001]:443",
			wantTarget: "[2001:db8::1]:443", wantHost: "2001:db8::1", wantPort: "443",
		},
		{
			name:    "IPv6 missing closing bracket",
			line:    "[2001:db8::1",
			wantErr: "missing closing bracket",
		},
		{
			name:    "IPv6 garbage literal",
			line:    "[gggg::1]",
			wantErr: "invalid IPv6 literal",
		},

		// --- malformed / partial entries ---
		{
			name:    "only a port",
			line:    ":8080",
			wantErr: "missing host before port",
		},
		{
			name:    "only a scheme prefix",
			line:    "https://",
			wantErr: "no host after scheme prefix",
		},
		{
			name:    "non-numeric port",
			line:    "example.com:abc",
			wantErr: "invalid port",
		},
		{
			name:    "port out of range",
			line:    "example.com:99999",
			wantErr: "invalid port",
		},
		{
			name:    "unsupported scheme",
			line:    "ftp://example.com",
			wantErr: "unsupported scheme",
		},
		{
			name:    "host name containing spaces",
			line:    "not a valid host name with spaces",
			wantErr: "invalid host name",
		},
		{
			name:    "host name containing tab",
			line:    "example\t.com",
			wantErr: "invalid host name",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := NormalizeLine(1, tt.line)

			if tt.wantBlank {
				if res.Target != nil || res.Invalid != nil {
					t.Fatalf("blank line must yield empty result, got %+v", res)
				}
				return
			}

			if tt.wantErr != "" {
				if res.Invalid == nil {
					t.Fatalf("expected invalid result containing %q, got %+v", tt.wantErr, res.Target)
				}
				if !strings.Contains(res.Invalid.Reason, tt.wantErr) {
					t.Fatalf("reason = %q, want substring %q", res.Invalid.Reason, tt.wantErr)
				}
				// Requirement 三.2: original spelling is retained, not rewritten.
				if res.Invalid.Entry.Raw != tt.line {
					t.Fatalf("invalid entry raw = %q, want %q", res.Invalid.Entry.Raw, tt.line)
				}
				return
			}

			if res.Invalid != nil {
				t.Fatalf("unexpected invalid result: %s", res.Invalid.Reason)
			}
			if res.Target == nil {
				t.Fatalf("expected target %q, got empty result", tt.wantTarget)
			}
			got := res.Target
			if got.Target != tt.wantTarget {
				t.Errorf("target = %q, want %q", got.Target, tt.wantTarget)
			}
			if got.Host != tt.wantHost {
				t.Errorf("host = %q, want %q", got.Host, tt.wantHost)
			}
			if got.Port != tt.wantPort {
				t.Errorf("port = %q, want %q", got.Port, tt.wantPort)
			}
			if got.Entry.Scheme != tt.wantScheme {
				t.Errorf("scheme = %q, want %q", got.Entry.Scheme, tt.wantScheme)
			}
			if got.Entry.Tail != tt.wantTail {
				t.Errorf("tail = %q, want %q", got.Entry.Tail, tt.wantTail)
			}
			if got.Entry.Raw != tt.line {
				t.Errorf("raw = %q, want %q", got.Entry.Raw, tt.line)
			}
		})
	}
}

func TestNormalize_Idempotent(t *testing.T) {
	// Requirement 二.1: normalizing the same input repeatedly must converge;
	// feeding the canonical target back in must not change it.
	lines := []string{
		"  HTTPS://EXAMPLE.COM:8443/path?x=1#f  ",
		"example.com.",
		"bücher.example",
		"[2001:0db8:0000:0000:0000:0000:0000:0001]:443",
	}
	for _, line := range lines {
		first := NormalizeLine(1, line)
		if first.Target == nil {
			t.Fatalf("first normalization failed for %q: %+v", line, first.Invalid)
		}
		again := NormalizeLine(2, first.Target.Target)
		if again.Target == nil || again.Target.Target != first.Target.Target {
			t.Fatalf("not idempotent: %q -> %q -> %v", line, first.Target.Target, again)
		}
		third := NormalizeLine(3, again.Target.Target)
		if third.Target.Target != first.Target.Target {
			t.Fatalf("third normalization drifted: %q vs %q", third.Target.Target, first.Target.Target)
		}
	}
}

func TestAccumulator_DedupFiveSpellings(t *testing.T) {
	// Acceptance 五.2: five spellings of one host collapse to one probe
	// target, and the trace retains all five original lines.
	lines := []string{
		"example.com",
		"EXAMPLE.COM",
		"example.com.",
		"https://example.com",
		"HTTPS://EXAMPLE.COM/path",
	}
	acc := NewAccumulator()
	for i, l := range lines {
		acc.Add(NormalizeLine(i+1, l))
	}
	targets := acc.Targets()
	if len(targets) != 1 {
		t.Fatalf("expected 1 unique target, got %d: %+v", len(targets), targets)
	}
	if targets[0].Target != "example.com" {
		t.Fatalf("target = %q, want example.com", targets[0].Target)
	}
	if len(targets[0].Source) != 5 {
		t.Fatalf("expected 5 traced source lines, got %d: %+v", len(targets[0].Source), targets[0].Source)
	}
	for i, l := range lines {
		if targets[0].Source[i].Raw != l {
			t.Errorf("source[%d] = %q, want %q", i, targets[0].Source[i].Raw, l)
		}
		if targets[0].Source[i].LineNo != i+1 {
			t.Errorf("source[%d] line number = %d, want %d", i, targets[0].Source[i].LineNo, i+1)
		}
	}
}

func TestIPv6_BracketedAndBareEquivalent(t *testing.T) {
	// Acceptance 五.3: bracketed and bare IPv6 spellings parse to the same
	// target and port.
	bare := NormalizeLine(1, "2001:db8::1")
	bracketed := NormalizeLine(2, "[2001:db8::1]")
	if bare.Target == nil || bracketed.Target == nil {
		t.Fatalf("both forms must parse: %+v %+v", bare, bracketed)
	}
	if bare.Target.Target != bracketed.Target.Target {
		t.Fatalf("targets differ: %q vs %q", bare.Target.Target, bracketed.Target.Target)
	}

	barePort := NormalizeLine(3, "[2001:db8::1]:8443")
	joined := joinHostPort(bare.Target.Host, "8443")
	if barePort.Target == nil || barePort.Target.Target != joined {
		t.Fatalf("IPv6 host:port join = %q, want %q", joined, barePort.Target)
	}
	if barePort.Target.Port != "8443" || barePort.Target.Host != "2001:db8::1" {
		t.Fatalf("host/port split wrong: %+v", barePort.Target)
	}
}

func TestAccumulator_InvalidCountedAndRestProbed(t *testing.T) {
	// Acceptance 五.4: malformed entries are skipped and counted while every
	// well-formed entry still becomes a probe target; the batch never aborts.
	lines := []string{
		"example.com",
		":8080",          // malformed: no host
		"https://",       // malformed: only scheme
		"  ",             // blank
		"example.org:99", // valid, unusual but in-range port
		"example.com",    // exact duplicate
		"EXAMPLE.COM",    // case-only duplicate
	}
	acc := NewAccumulator()
	for i, l := range lines {
		acc.Add(NormalizeLine(i+1, l))
	}
	if len(acc.Invalid) != 2 {
		t.Fatalf("expected 2 invalid entries, got %d: %+v", len(acc.Invalid), acc.Invalid)
	}
	targets := acc.Targets()
	if len(targets) != 2 {
		t.Fatalf("expected 2 unique targets, got %d: %+v", len(targets), targets)
	}
	want := map[string]bool{"example.com": true, "example.org:99": true}
	for _, tt := range targets {
		if !want[tt.Target] {
			t.Errorf("unexpected target %q", tt.Target)
		}
	}
	if targets[0].Target != "example.com" || len(targets[0].Source) != 3 {
		t.Fatalf("duplicate lines should merge with all sources kept: %+v", targets[0])
	}
}

func TestWriteTrace_JSONLinesRoundTrip(t *testing.T) {
	// Requirement 二.4: trace data is separate from the probe output and
	// each line is a self-contained JSON object the downstream can decode.
	acc := NewAccumulator()
	acc.Add(NormalizeLine(1, "example.com"))
	acc.Add(NormalizeLine(2, "EXAMPLE.COM."))
	acc.Add(NormalizeLine(3, "  https://example.com/x "))
	acc.Add(NormalizeLine(4, ":bad"))

	var buf bytes.Buffer
	if err := acc.WriteTrace(&buf); err != nil {
		t.Fatalf("WriteTrace: %s", err)
	}
	dec := json.NewDecoder(&buf)
	var targetLines, invalidLines, summaryLines int
	for dec.More() {
		var raw map[string]json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			t.Fatalf("trace line is not valid JSON: %s", err)
		}
		switch {
		case raw["target"] != nil:
			targetLines++
		case raw["invalid"] != nil:
			invalidLines++
		case raw["invalid_count"] != nil:
			summaryLines++
		default:
			t.Errorf("unrecognized trace object: %v", raw)
		}
	}
	if targetLines != 1 || invalidLines != 1 || summaryLines != 1 {
		t.Fatalf("trace line counts wrong: targets=%d invalid=%d summary=%d", targetLines, invalidLines, summaryLines)
	}
}
