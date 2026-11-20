package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

type probeArgs []string

func (p *probeArgs) Set(val string) error {
	*p = append(*p, val)
	return nil
}

func (p probeArgs) String() string {
	return strings.Join(p, ",")
}

// backgroundCtx is a single indirection so probe/diag code stays free of
// context plumbing while remaining testable.
func backgroundCtx() context.Context {
	return context.Background()
}

func main() {

	// concurrency flag
	var concurrency int
	flag.IntVar(&concurrency, "c", 20, "set the concurrency level (split equally between HTTPS and HTTP requests)")

	// probe flags
	var probes probeArgs
	flag.Var(&probes, "p", "add additional probe (proto:port)")

	// skip default probes flag
	var skipDefault bool
	flag.BoolVar(&skipDefault, "s", false, "skip the default probes (http:80 and https:443)")

	// timeout flag: independent budget for each of the two probe phases
	// (connect, and post-connect response reading)
	var to int
	flag.IntVar(&to, "t", 10000, "per-phase timeout (milliseconds); total per-target budget is bounded regardless of retries")

	// prefer https
	var preferHTTPS bool
	flag.BoolVar(&preferHTTPS, "prefer-https", false, "only try plain HTTP if HTTPS fails")

	// HTTP method to use
	var method string
	flag.StringVar(&method, "method", "GET", "HTTP method to use")

	// diagnostic channel: empty means disabled and the tool behaves exactly
	// as before the change. A path writes JSONL records there; "-" is stderr.
	var diagPath string
	flag.StringVar(&diagPath, "diag", "", "enable machine-readable diagnostics channel: JSONL file path, or '-' for stderr (stdout remains available-target-only)")

	// fixed retry cap per target, effective only when -diag is enabled
	var maxRetries int
	flag.IntVar(&maxRetries, "retries", 1, "max retries per target for retryable failure classes (only used with -diag)")

	flag.Parse()

	timeout := time.Duration(to) * time.Millisecond

	// Diagnostic channel disabled: exact legacy behavior, no retries, no
	// classification, no deduplication beyond the original pipeline.
	if diagPath == "" {
		runLegacy(concurrency, timeout, method, preferHTTPS, probes, skipDefault)
		return
	}

	sink, err := openDiagSink(diagPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to open diagnostics channel %q: %s\n", diagPath, err)
		os.Exit(1)
	}
	defer sink.Close()

	runDiagnostics(concurrency, timeout, maxRetries, method, preferHTTPS, probes, skipDefault, sink)
}

func openDiagSink(path string) (*DiagSink, error) {
	if path == "-" {
		// stderr is managed by the runtime; the sink must not close it.
		s := NewDiagSink(nil)
		s.w = nopWriteCloser{os.Stderr}
		s.enc = newJSONEncoder(s.w)
		s.closable = false
		return s, nil
	}
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	return NewDiagSink(f), nil
}

// runDiagnostics is the classified, retry-aware pipeline. stdout still carries
// one line per available target only; every final verdict (available or not)
// is emitted once to the diagnostic sink.
func runDiagnostics(concurrency int, timeout time.Duration, maxRetries int, method string, preferHTTPS bool, probes []string, skipDefault bool, sink *DiagSink) {
	prober := &Prober{
		connectPhaseTimeout: timeout,
		readPhaseTimeout:    timeout,
		// Absolute wall-clock cap for one target regardless of retry count:
		// at most (maxRetries+1) complete attempts, each bounded by the two
		// independent phase budgets. Retries therefore never make the budget
		// grow beyond this fixed, declared multiple.
		overallDeadline: time.Duration(maxRetries+1) * (timeout + timeout),
		maxRetries:      maxRetries,
		method:          method,
		verifyCerts:     true,
	}
	registry := newVerdictRegistry()

	httpsURLs := make(chan string)
	httpURLs := make(chan string)
	output := make(chan string)

	// HTTPS workers — HTTPS is always attempted before the HTTP fallback;
	// this ordering is unchanged from the legacy pipeline.
	var httpsWG sync.WaitGroup
	for i := 0; i < concurrency/2; i++ {
		httpsWG.Add(1)
		go func() {
			for hostport := range httpsURLs {
				target := "https://" + normalizeDefaultPort(hostport, "443")

				v, leader := registry.runProbe(prober, target)
				if !leader {
					continue
				}

				// Every target yields exactly one diagnostic record.
				sink.Emit(v)
				if v.available() {
					output <- target
					if preferHTTPS {
						continue
					}
				}

				// Fallback to plaintext on the same host:port. Only the
				// leader schedules it, so it is enqueued at most once.
				httpURLs <- hostport
			}
			httpsWG.Done()
		}()
	}

	// HTTP workers
	var httpWG sync.WaitGroup
	for i := 0; i < concurrency/2; i++ {
		httpWG.Add(1)
		go func() {
			for hostport := range httpURLs {
				target := "http://" + normalizeDefaultPort(hostport, "80")

				v, leader := registry.runProbe(prober, target)
				if !leader {
					continue
				}
				sink.Emit(v)
				if v.available() {
					output <- target
				}
			}
			httpWG.Done()
		}()
	}

	go func() {
		httpsWG.Wait()
		close(httpURLs)
	}()

	// stdout writer: available targets only, one per line, same format as
	// the legacy output.
	var outputWG sync.WaitGroup
	outputWG.Add(1)
	go func() {
		for o := range output {
			fmt.Println(o)
		}
		outputWG.Done()
	}()

	go func() {
		httpWG.Wait()
		close(output)
	}()

	feedStdin(httpsURLs, httpURLs, probes, skipDefault)
	close(httpsURLs)

	outputWG.Wait()
}

// normalizeDefaultPort appends the scheme's default port when the input has no
// explicit port. Explicit ports (including additional -p probes) are preserved,
// so the same host hit on different ports yields distinct target keys whose
// verdicts can never overwrite each other.
func normalizeDefaultPort(hostport, defaultPort string) string {
	if _, _, err := splitHostPort(hostport); err == nil {
		return hostport
	}
	return hostport + ":" + defaultPort
}
