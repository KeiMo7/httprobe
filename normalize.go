package main

import (
	"net"
	"strconv"
	"strings"

	"golang.org/x/net/idna"
)

// RawEntry records everything known about one physical input line so that
// downstream consumers can map a probe target back to the exact line(s) it
// came from. Nothing in this file performs network or DNS lookups: only
// string and encoding transformations are applied.
type RawEntry struct {
	LineNo int    `json:"line"`             // 1-based position in the input stream
	Raw    string `json:"raw"`              // the line as read, before any trimming
	Scheme string `json:"scheme,omitempty"` // original-cased scheme prefix, if any
	Tail   string `json:"tail,omitempty"`   // original path/query/fragment, if any
}

// ParsedTarget is the result of successfully normalizing one input line.
type ParsedTarget struct {
	// Target is the canonical host[:port] string handed to the probe layer.
	// It is suitable for direct use by net/http: IPv6 literals are always
	// bracketed, host names are lower-cased and IDNs are punycode-encoded.
	Target string
	// Host and Port hold the canonical components; Port is empty when the
	// input line did not carry an explicit port.
	Host  string
	Port  string
	Entry RawEntry
}

// InvalidEntry records an input line that could not be turned into a probe
// target, together with a machine-readable reason.
type InvalidEntry struct {
	Entry  RawEntry `json:"entry"`
	Reason string   `json:"reason"`
}

// Result is the outcome of consuming one input line. Exactly one of Target
// or Reason is meaningful (blank lines yield neither).
type Result struct {
	Target  *ParsedTarget
	Invalid *InvalidEntry
}

// idnaProfile maps internationalized domain names to their ASCII (punycode)
// form while rejecting names that violate label rules. It performs no
// lookups; the conversion is purely algorithmic.
var idnaProfile = idna.New(
	idna.ValidateLabels(true),
	idna.VerifyDNSLength(true),
)

// NormalizeLine turns one raw input line into a canonical probe target.
//
// A blank line (empty once surrounding whitespace is removed) yields a nil
// result and no error: it is simply skipped. A non-blank line that cannot be
// parsed yields a Result carrying an InvalidEntry with a reason; callers
// skip it and keep processing the rest of the batch.
func NormalizeLine(lineNo int, line string) Result {
	entry := RawEntry{LineNo: lineNo, Raw: line}

	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return Result{}
	}

	// Split off an optional scheme prefix. The scheme is case-insensitive and
	// must look like one (leading alpha, only alphanumerics/+/-/. after it).
	rest := trimmed
	if i := strings.Index(trimmed, "://"); i >= 0 {
		scheme := trimmed[:i]
		if !isScheme(scheme) {
			return invalid(entry, "malformed scheme prefix: "+scheme)
		}
		// Only the schemes the probe layer speaks are accepted; other
		// prefixes are unparseable rather than silently mis-probed.
		lowerScheme := strings.ToLower(scheme)
		if lowerScheme != "http" && lowerScheme != "https" {
			return invalid(entry, "unsupported scheme prefix: "+scheme)
		}
		entry.Scheme = scheme
		rest = trimmed[i+3:]
	}

	if rest == "" {
		return invalid(entry, "no host after scheme prefix")
	}

	// A path/query/fragment never belongs in the probe target; keep the
	// original text in the trace entry and work on the authority only.
	authority := rest
	if slash := strings.IndexAny(rest, "/?#"); slash >= 0 {
		entry.Tail = rest[slash:]
		authority = rest[:slash]
	}
	if authority == "" {
		return invalid(entry, "no host before path")
	}

	host, port, perr := splitHostPort(authority)
	if perr != "" {
		return invalid(entry, perr)
	}

	host, perr = canonicalHost(host)
	if perr != "" {
		// Requirement 三.2: an IDN conversion failure keeps the original
		// spelling and is marked unusable rather than silently rewritten.
		return invalid(entry, perr)
	}

	// Assemble the canonical target: IPv6 hosts are always bracketed, even
	// without an explicit port, so every normalized target is unambiguous
	// and directly usable by the connection layer. Plain hosts keep their
	// historic "host" / "host:port" spelling.
	target := host
	if strings.Contains(host, ":") {
		target = "[" + host + "]"
	}
	if port != "" {
		target = net.JoinHostPort(host, port)
	}

	return Result{Target: &ParsedTarget{
		Target: target,
		Host:   host,
		Port:   port,
		Entry:  entry,
	}}
}

// splitHostPort splits an authority section (scheme and tail already removed)
// into a host and an optional port, parsing IPv6 literals correctly whether
// or not they are bracketed so colons inside an address are never mistaken
// for the port separator.
func splitHostPort(authority string) (host, port, reason string) {
	if strings.HasPrefix(authority, "[") {
		// Bracketed form: [IPv6] or [IPv6]:port
		closeBracket := strings.Index(authority, "]")
		if closeBracket < 0 {
			return "", "", "missing closing bracket in IPv6 literal"
		}
		host = authority[1:closeBracket]
		remainder := authority[closeBracket+1:]
		if remainder == "" {
			return host, "", ""
		}
		if remainder[0] != ':' {
			return "", "", "unexpected text after IPv6 literal: " + remainder
		}
		port = remainder[1:]
		if port == "" {
			return "", "", "missing port after colon"
		}
		if p, ok := validPort(port); !ok {
			return "", "", "invalid port: " + port
		} else {
			return host, p, ""
		}
	}

	// Unbracketed. More than one colon means an IPv6 literal without a port
	// (an unbracketed IPv6 with a port would be ambiguous, which is exactly
	// why the bracketed form exists); a single colon is host:port.
	switch strings.Count(authority, ":") {
	case 0:
		return authority, "", ""
	case 1:
		i := strings.Index(authority, ":")
		host = authority[:i]
		port = authority[i+1:]
		if host == "" {
			return "", "", "missing host before port"
		}
		if port == "" {
			return "", "", "missing port after colon"
		}
		p, ok := validPort(port)
		if !ok {
			return "", "", "invalid port: " + port
		}
		return host, p, ""
	default:
		// Unbracketed IPv6 literal.
		return authority, "", ""
	}
}

// validPort accepts numeric ports in the range 1..65535 and returns them in
// their canonical (trimmed, leading-zero-free) spelling.
func validPort(port string) (string, bool) {
	if port == "" || !isAllDigits(port) {
		return "", false
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return "", false
	}
	return strconv.Itoa(n), true
}

// canonicalHost normalizes a host string into the form used for connections
// and as the basis of the dedup key. No name resolution is performed.
func canonicalHost(host string) (string, string) {
	if host == "" {
		return "", "empty host"
	}

	// IPv6 literals (brackets were already stripped) go through the standard
	// parser, which both validates and yields one canonical spelling.
	if strings.Contains(host, ":") {
		ip := net.ParseIP(host)
		if ip == nil || ip.To4() != nil || !strings.Contains(host, ":") {
			return "", "invalid IPv6 literal: " + host
		}
		// Strip any zone for a stable, connectable canonical form.
		if z := strings.Index(host, "%"); z >= 0 {
			host = host[:z]
			ip = net.ParseIP(host)
			if ip == nil {
				return "", "invalid IPv6 literal: " + host
			}
		}
		return ip.String(), ""
	}

	// Drop a single trailing dot: "example.com." is the same host as
	// "example.com". More than one trailing dot means a malformed name.
	trimmed := host
	if strings.HasSuffix(trimmed, ".") {
		trimmed = strings.TrimSuffix(trimmed, ".")
		if trimmed == "" || strings.HasSuffix(trimmed, ".") {
			return "", "invalid host name: " + host
		}
	}

	if net.ParseIP(trimmed) != nil {
		// Numeric IPv4 literal: keep the canonical spelling from net.IP.
		return net.ParseIP(trimmed).String(), ""
	}

	// Domain names. Lower-case first so ASCII and IDN inputs share one path.
	lowered := strings.ToLower(trimmed)

	// Reject whitespace and control characters that may not appear in a
	// host name before any IDN processing, so bad input is reported instead
	// of being passed downstream.
	for _, r := range lowered {
		if r <= ' ' || r == 0x7f {
			return "", "invalid host name: " + host
		}
	}

	// Punycode-encode non-ASCII labels via the IDNA profile.
	ascii, err := idnaProfile.ToASCII(lowered)
	if err != nil {
		return "", "invalid or unconvertible host name: " + host
	}
	return ascii, ""
}

func isScheme(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		switch {
		case i == 0 && !isAlpha(r):
			return false
		case isAlnum(r) || r == '+' || r == '-' || r == '.':
		default:
			return false
		}
	}
	return true
}

func isAlpha(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
}

func isAlnum(r rune) bool {
	return isAlpha(r) || (r >= '0' && r <= '9')
}

func isAllDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func invalid(entry RawEntry, reason string) Result {
	return Result{Invalid: &InvalidEntry{Entry: entry, Reason: reason}}
}

// joinHostPort combines a canonical host with a probe port. net.JoinHostPort
// guarantees IPv6 literals are bracketed so the separator is unambiguous and
// the result can be used directly by the connection layer. For plain host
// names the output is identical to the historic "host:port" formatting.
func joinHostPort(host, port string) string {
	return net.JoinHostPort(host, port)
}

// plural returns the singular suffix when n == 1, pluralSuffix otherwise.
func plural(n int, singular, pluralSuffix string) string {
	if n == 1 {
		return singular
	}
	return pluralSuffix
}
