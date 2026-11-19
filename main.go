package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
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

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

// run is the testable entry point. It preserves the original command-line
// surface and stdout format; new behaviour is opt-in via extra flags or is
// purely internal (retries, ordering, cancellation).
func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("httprobe", flag.ContinueOnError)
	fs.SetOutput(stderr)

	// concurrency flag
	var concurrency int
	fs.IntVar(&concurrency, "c", 20, "set the concurrency level (split equally between HTTPS and HTTP requests)")

	// probe flags
	var probes probeArgs
	fs.Var(&probes, "p", "add additional probe (proto:port)")

	// skip default probes flag
	var skipDefault bool
	fs.BoolVar(&skipDefault, "s", false, "skip the default probes (http:80 and https:443)")

	// timeout flag
	var to int
	fs.IntVar(&to, "t", 10000, "timeout (milliseconds)")

	// prefer https
	var preferHTTPS bool
	fs.BoolVar(&preferHTTPS, "prefer-https", false, "only try plain HTTP if HTTPS fails")

	// HTTP method to use
	var method string
	fs.StringVar(&method, "method", "GET", "HTTP method to use")

	// New, optional flags. Defaults preserve the original behaviour.
	var attempts int
	fs.IntVar(&attempts, "attempts", 1, "attempts per target before recording a terminal failure")
	var jsonOut bool
	fs.BoolVar(&jsonOut, "json", false, "emit structured results (url, status, attempts, last_error) instead of bare URLs")
	var outputPath string
	fs.StringVar(&outputPath, "o", "", "write results to a file (completed results survive cancellation)")
	var showProgress bool
	fs.BoolVar(&showProgress, "progress", false, "print batch progress to stderr")
	var inputPath string
	fs.StringVar(&inputPath, "i", "", "read domains from a file instead of stdin")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}

	if concurrency < 1 {
		concurrency = 1
	}
	if attempts < 1 {
		attempts = 1
	}

	timeout := time.Duration(to) * time.Millisecond

	tr := &http.Transport{
		MaxIdleConns:      30,
		IdleConnTimeout:   time.Second,
		DisableKeepAlives: true,
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		DialContext: (&net.Dialer{
			Timeout:   timeout,
			KeepAlive: time.Second,
		}).DialContext,
	}

	re := func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	client := &http.Client{
		Transport:     tr,
		CheckRedirect: re,
		Timeout:       timeout,
	}

	// Resolve the input source.
	in := stdin
	if inputPath != "" {
		f, err := os.Open(inputPath)
		if err != nil {
			fmt.Fprintf(stderr, "failed to read input: %v\n", err)
			return 0
		}
		defer f.Close()
		in = f
	}
	if in == nil {
		in = os.Stdin
	}

	// Read the whole target list first so progress and results are computed
	// against a known total. Input problems are reported at their line.
	domains, issues := readDomains(in, maxInputLineBytes)
	for _, issue := range issues {
		fmt.Fprintf(stderr, "failed to read input: %s\n", issue.Error())
	}

	plan := buildPlan(domains, probes, skipDefault)

	p := newProber(client, method, timeout, concurrency, attempts)
	p.PreferHTTPS = preferHTTPS

	sink, err := newResultSink(outputPath, jsonOut, stdout)
	if err != nil {
		fmt.Fprintf(stderr, "failed to open output: %v\n", err)
		return 1
	}

	// Cancel cleanly on Ctrl-C / SIGTERM. Completed results are still written.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	ow := newOrderedWriter(sink)
	p.OnResult = ow.Record

	if showProgress {
		var mu sync.Mutex
		var last time.Time
		p.OnProgress = func(done, total int) {
			mu.Lock()
			defer mu.Unlock()
			now := time.Now()
			if done != total && now.Sub(last) < time.Second {
				return
			}
			last = now
			fmt.Fprintf(stderr, "progress: %d/%d targets\n", done, total)
		}
	}

	results := p.Probe(ctx, plan)
	ow.FlushAll(results)

	cancelled := ctx.Err() != nil
	if err := sink.Close(); err != nil {
		fmt.Fprintf(stderr, "failed to write output: %v\n", err)
		if outputPath != "" {
			return 1
		}
	}

	if cancelled {
		fmt.Fprintln(stderr, "probe cancelled; completed results were kept")
		return 130
	}
	return 0
}

// orderedWriter emits results in target order even though workers finish out
// of order. Results that complete after a gap are buffered until the gap
// fills; FlushAll writes whatever is left once every target has a terminal
// state.
type orderedWriter struct {
	sink resultSink

	mu      sync.Mutex
	next    int
	pending map[int]probeResult
	err     error
}

func newOrderedWriter(sink resultSink) *orderedWriter {
	return &orderedWriter{sink: sink, pending: make(map[int]probeResult)}
}

func (w *orderedWriter) Record(r probeResult) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.pending[r.Target.Index] = r
	for {
		next, ok := w.pending[w.next]
		if !ok {
			return
		}
		delete(w.pending, w.next)
		w.next++
		if w.err != nil {
			continue
		}
		if err := w.sink.WriteResult(next); err != nil {
			w.err = err
		}
	}
}

// FlushAll writes any results not already emitted, in target order. The prober
// guarantees every target has a terminal state on return, so this covers
// cancellation and any target whose index sits after an untried gap.
func (w *orderedWriter) FlushAll(results []probeResult) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, r := range results {
		if r.Target.Index < w.next {
			continue
		}
		w.next = r.Target.Index + 1
		if w.err != nil {
			continue
		}
		if err := w.sink.WriteResult(r); err != nil {
			w.err = err
		}
	}
	w.pending = make(map[int]probeResult)
	if w.next < len(results) && w.err == nil {
		w.err = fmt.Errorf("internal: %d targets missing terminal results", len(results)-w.next)
	}
}
