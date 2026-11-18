package main

import (
	"bufio"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"
)

type severity string

const (
	severityHigh   severity = "high"
	severityMedium severity = "medium"
	severityNote   severity = "note"
)

type probeTarget struct {
	domain string
	line   int
	column int
	length int
}

type finding struct {
	target probeTarget
	scheme string
	port   string
	ruleID string
	level  severity
}

type runOptions struct {
	concurrency int
	probes      []string
	skipDefault bool
	timeout     time.Duration
	preferHTTPS bool
	method      string
	input       io.Reader
	output      io.Writer
	sarifFile   string
	inputFile   string
	failAfter   int
	repoRoot    string
	flushEvery  int
}

type probeArgs []string

func (p *probeArgs) Set(val string) error {
	*p = append(*p, val)
	return nil
}

func (p probeArgs) String() string {
	return strings.Join(p, ",")
}

func main() {
	os.Exit(run(os.Args[0], os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(program string, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet(program, flag.ContinueOnError)
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

	// SARIF output
	var sarifFile string
	fs.StringVar(&sarifFile, "sarif", "", "write probe results to the specified file in SARIF 2.1.0 format")

	// input source for SARIF physical locations
	var inputFile string
	fs.StringVar(&inputFile, "input", "", "read line-delimited domains from the named file instead of stdin")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}

	// make an actual time.Duration out of the timeout
	timeout := time.Duration(to * 1000000)

	opts := runOptions{
		concurrency: concurrency,
		probes:      probes,
		skipDefault: skipDefault,
		timeout:     timeout,
		preferHTTPS: preferHTTPS,
		method:      method,
		input:       stdin,
		output:      stdout,
		sarifFile:   sarifFile,
		inputFile:   inputFile,
		flushEvery:  sarifFlushEvery,
	}

	return execute(opts, stderr)
}

func execute(opts runOptions, stderr io.Writer) int {
	if opts.inputFile != "" {
		inputFile, err := os.Open(opts.inputFile)
		if err != nil {
			fmt.Fprintf(stderr, "failed to open input: %s\n", err)
			return 1
		}
		defer inputFile.Close()
		opts.input = inputFile
	}

	var tr = &http.Transport{
		MaxIdleConns:      30,
		IdleConnTimeout:   time.Second,
		DisableKeepAlives: true,
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
	}

	dialer := &net.Dialer{
		Timeout:   opts.timeout,
		KeepAlive: time.Second,
	}
	if opts.failAfter > 0 {
		dialer.Control = failingControl(opts.failAfter)
	}

	re := func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	tr.DialContext = dialer.DialContext

	client := &http.Client{
		Transport:     tr,
		CheckRedirect: re,
		Timeout:       opts.timeout,
	}

	var sarifWriter *sarifOutput
	var sarifErr error
	var sarifErrMu sync.Mutex
	if opts.sarifFile != "" {
		root := opts.repoRoot
		if root == "" {
			root = repositoryRoot()
		}
		writer, err := newSARIFOutput(opts.sarifFile, root, opts.inputFile, opts.flushEvery)
		if err != nil {
			fmt.Fprintf(stderr, "failed to start SARIF output: %s\n", err)
			return 1
		}
		sarifWriter = writer
		defer func() {
			sarifErrMu.Lock()
			finalErr := sarifErr
			sarifErrMu.Unlock()
			if err := sarifWriter.Close(finalErr); err != nil {
				fmt.Fprintf(stderr, "failed to write SARIF output: %s\n", err)
			}
		}()
	}

	// domain/port pairs are initially sent on the httpsURLs channel.
	// If they are listening and the --prefer-https flag is set then
	// no HTTP check is performed; otherwise they're put onto the httpURLs
	// channel for an HTTP check.
	httpsURLs := make(chan probeTarget)
	httpURLs := make(chan probeTarget)
	output := make(chan finding)

	workerCount := opts.concurrency / 2
	if workerCount < 1 {
		workerCount = 1
	}

	// HTTPS workers
	var httpsWG sync.WaitGroup
	for i := 0; i < workerCount; i++ {
		httpsWG.Add(1)

		go func() {
			for target := range httpsURLs {

				// always try HTTPS first
				withProto := "https://" + target.domain
				if isListening(client, withProto, opts.method) {
					output <- newFinding(target, "https")

					// skip trying HTTP if --prefer-https is set
					if opts.preferHTTPS {
						continue
					}
				}

				httpURLs <- target
			}

			httpsWG.Done()
		}()
	}

	// HTTP workers
	var httpWG sync.WaitGroup
	for i := 0; i < workerCount; i++ {
		httpWG.Add(1)

		go func() {
			for target := range httpURLs {
				withProto := "http://" + target.domain
				if isListening(client, withProto, opts.method) {
					output <- newFinding(target, "http")
					continue
				}
			}

			httpWG.Done()
		}()
	}

	// Close the httpURLs channel when the HTTPS workers are done
	go func() {
		httpsWG.Wait()
		close(httpURLs)
	}()

	// Output worker
	var outputWG sync.WaitGroup
	outputWG.Add(1)
	go func() {
		for hit := range output {
			fmt.Fprintln(opts.output, hit.scheme+"://"+hit.target.domain)
			if sarifWriter != nil {
				if err := sarifWriter.WriteResult(hit); err != nil {
					fmt.Fprintf(stderr, "failed to write SARIF output: %s\n", err)
					sarifErrMu.Lock()
					if sarifErr == nil {
						sarifErr = err
					}
					sarifErrMu.Unlock()
				}
			}
		}
		outputWG.Done()
	}()

	// Close the output channel when the HTTP workers are done
	go func() {
		httpWG.Wait()
		close(output)
	}()

	// accept domains on stdin
	sc := bufio.NewScanner(opts.input)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		rawLine := sc.Text()
		trimmed := strings.TrimSpace(rawLine)
		domain := strings.ToLower(trimmed)
		column := strings.Index(rawLine, trimmed) + 1
		if trimmed == "" {
			column = 1
		}
		target := probeTarget{
			domain: domain,
			line:   lineNo,
			column: column,
			length: utf16Length(trimmed),
		}

		// submit standard port checks
		if !opts.skipDefault {
			httpsURLs <- target
		}

		// Adding port templates
		xlarge := []string{"81", "300", "591", "593", "832", "981", "1010", "1311", "2082", "2087", "2095", "2096", "2480", "3000", "3128", "3333", "4243", "4567", "4711", "4712", "4993", "5000", "5104", "5108", "5800", "6543", "7000", "7396", "7474", "8000", "8001", "8008", "8014", "8042", "8069", "8080", "8081", "8088", "8090", "8091", "8118", "8123", "8172", "8222", "8243", "8280", "8281", "8333", "8443", "8500", "8834", "8880", "8888", "8983", "9000", "9043", "9060", "9080", "9090", "9091", "9200", "9443", "9800", "9981", "12443", "16080", "18091", "18092", "20720", "28017"}
		large := []string{"81", "591", "2082", "2087", "2095", "2096", "3000", "8000", "8001", "8008", "8080", "8083", "8443", "8834", "8888"}

		// submit any additional proto:port probes
		for _, p := range opts.probes {
			switch p {
			case "xlarge":
				for _, port := range xlarge {
					portTarget := target
					portTarget.domain = fmt.Sprintf("%s:%s", domain, port)
					httpsURLs <- portTarget
				}
			case "large":
				for _, port := range large {
					portTarget := target
					portTarget.domain = fmt.Sprintf("%s:%s", domain, port)
					httpsURLs <- portTarget
				}
			default:
				pair := strings.SplitN(p, ":", 2)
				if len(pair) != 2 {
					continue
				}

				// This is a little bit funny as "https" will imply an
				// http check as well unless the --prefer-https flag is
				// set. On balance I don't think that's *such* a bad thing
				// but it is maybe a little unexpected.
				portTarget := target
				portTarget.domain = fmt.Sprintf("%s:%s", domain, pair[1])
				if strings.ToLower(pair[0]) == "https" {
					httpsURLs <- portTarget
				} else {
					httpURLs <- portTarget
				}
			}
		}
	}

	// once we've sent all the URLs off we can close the
	// input/httpsURLs channel. The workers will finish what they're
	// doing and then call 'Done' on the WaitGroup
	close(httpsURLs)

	// check there were no errors reading stdin (unlikely)
	if err := sc.Err(); err != nil {
		fmt.Fprintf(stderr, "failed to read input: %s\n", err)
		sarifErrMu.Lock()
		if sarifErr == nil {
			sarifErr = err
		}
		sarifErrMu.Unlock()
	}

	// Wait until the output waitgroup is done
	outputWG.Wait()

	if opts.failAfter > 0 {
		sarifErrMu.Lock()
		if sarifErr == nil {
			sarifErr = fmt.Errorf("probe transport failed: %d or more probes were attempted", opts.failAfter)
		}
		sarifErrMu.Unlock()
	}

	return 0
}

func isListening(client *http.Client, url, method string) bool {

	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return false
	}

	req.Header.Add("Connection", "close")
	req.Close = true

	resp, err := client.Do(req)
	if resp != nil {
		io.Copy(ioutil.Discard, resp.Body)
		resp.Body.Close()
	}

	if err != nil {
		return false
	}

	return true
}

func failingControl(failAfter int) func(string, string, syscall.RawConn) error {
	var mu sync.Mutex
	count := 0
	return func(network, address string, conn syscall.RawConn) error {
		mu.Lock()
		count++
		current := count
		mu.Unlock()

		if current >= failAfter {
			return fmt.Errorf("injected probe failure for %s %s", network, address)
		}
		return nil
	}
}
