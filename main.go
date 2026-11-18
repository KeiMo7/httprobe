package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
)

type probeArgs []string

func (p *probeArgs) Set(val string) error {
	*p = append(*p, val)
	return nil
}

func (p probeArgs) String() string {
	return strings.Join(p, ",")
}

type options struct {
	concurrency      int
	probes           probeArgs
	skipDefault      bool
	timeoutMS        int
	preferHTTPS      bool
	method           string
	configPath       string
	proxy            string
	proxyUserEnv     string
	proxyPasswordEnv string
	connectTimeoutMS int
	readTimeoutMS    int
	failThreshold    int
	summary          bool
	summarySet       bool
	help             bool
}

type target struct {
	host string
	rule string
}

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "httprobe: %v\n", err)
		os.Exit(2)
	}
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	opts, err := parseOptions(args, stderr)
	if err != nil {
		return err
	}
	if opts.help {
		return nil
	}

	plan, err := buildPlan(opts, os.LookupEnv)
	if err != nil {
		return err
	}

	return execute(opts, plan, stdin, stdout, stderr)
}

func parseOptions(args []string, stderr io.Writer) (options, error) {
	var opts options

	fs := flag.NewFlagSet("httprobe", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.IntVar(&opts.concurrency, "c", 20, "set the concurrency level (split equally between HTTPS and HTTP requests)")
	fs.Var(&opts.probes, "p", "add additional probe (proto:port)")
	fs.BoolVar(&opts.skipDefault, "s", false, "skip the default probes (http:80 and https:443)")
	fs.IntVar(&opts.timeoutMS, "t", 10000, "timeout (milliseconds)")
	fs.BoolVar(&opts.preferHTTPS, "prefer-https", false, "only try plain HTTP if HTTPS fails")
	fs.StringVar(&opts.method, "method", "GET", "HTTP method to use")
	fs.StringVar(&opts.configPath, "config", "", "JSON configuration file for targets, proxy rules and timeouts")
	fs.StringVar(&opts.proxy, "proxy", "", "forward every probe through this HTTP proxy")
	fs.StringVar(&opts.proxyUserEnv, "proxy-user-env", "", "environment variable containing the proxy username")
	fs.StringVar(&opts.proxyPasswordEnv, "proxy-password-env", "", "environment variable containing the proxy password")
	fs.IntVar(&opts.connectTimeoutMS, "connect-timeout", 0, "proxy/target connection timeout in milliseconds")
	fs.IntVar(&opts.readTimeoutMS, "read-timeout", 0, "response read timeout in milliseconds")
	fs.IntVar(&opts.failThreshold, "proxy-fail-threshold", 0, "consecutive proxy failures before opening its circuit")
	fs.BoolVar(&opts.summary, "summary", false, "print per-rule result summary to stderr")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			opts.help = true
			return opts, nil
		}
		return opts, err
	}
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "summary" {
			opts.summarySet = true
		}
	})
	if opts.concurrency < 2 {
		return opts, fmt.Errorf("-c must be at least 2")
	}
	if opts.timeoutMS < 0 || opts.connectTimeoutMS < 0 || opts.readTimeoutMS < 0 || opts.failThreshold < 0 {
		return opts, fmt.Errorf("timeouts and -proxy-fail-threshold must not be negative")
	}
	if opts.configPath != "" && opts.proxy != "" {
		return opts, fmt.Errorf("-config and -proxy cannot be used together")
	}
	if opts.proxy == "" && (opts.proxyUserEnv != "" || opts.proxyPasswordEnv != "") {
		return opts, fmt.Errorf("-proxy-user-env and -proxy-password-env require -proxy")
	}

	return opts, nil
}

type event struct {
	stdout string
	stderr string
}

func execute(opts options, plan *runtimePlan, stdin io.Reader, stdout, stderr io.Writer) error {
	httpsURLs := make(chan target)
	httpURLs := make(chan target)
	events := make(chan event)

	var httpsWG sync.WaitGroup
	for i := 0; i < opts.concurrency/2; i++ {
		httpsWG.Add(1)
		go func() {
			for tgt := range httpsURLs {
				route := plan.router.routeFor(tgt.host, tgt.rule)
				withProto := "https://" + tgt.host
				result := probeURL(route, withProto, opts.method)
				plan.stats.record(route, result)

				if result.ok {
					events <- event{stdout: formatSuccess(withProto, route, plan.proxyMode)}
					if opts.preferHTTPS {
						continue
					}
				} else if plan.proxyMode {
					events <- event{stderr: formatFailure(withProto, route, result)}
				}

				httpURLs <- tgt
			}
			httpsWG.Done()
		}()
	}

	var httpWG sync.WaitGroup
	for i := 0; i < opts.concurrency/2; i++ {
		httpWG.Add(1)
		go func() {
			for tgt := range httpURLs {
				route := plan.router.routeFor(tgt.host, tgt.rule)
				withProto := "http://" + tgt.host
				result := probeURL(route, withProto, opts.method)
				plan.stats.record(route, result)

				if result.ok {
					events <- event{stdout: formatSuccess(withProto, route, plan.proxyMode)}
				} else if plan.proxyMode {
					events <- event{stderr: formatFailure(withProto, route, result)}
				}
			}
			httpWG.Done()
		}()
	}

	go func() {
		httpsWG.Wait()
		close(httpURLs)
	}()

	var eventWG sync.WaitGroup
	eventWG.Add(1)
	go func() {
		for evt := range events {
			if evt.stdout != "" {
				fmt.Fprintln(stdout, evt.stdout)
			}
			if evt.stderr != "" {
				fmt.Fprint(stderr, evt.stderr)
			}
		}
		eventWG.Done()
	}()

	go func() {
		httpWG.Wait()
		close(events)
	}()

	submitTargets(opts, plan.targets, stdin, httpsURLs, httpURLs, stderr)
	close(httpsURLs)
	eventWG.Wait()

	if plan.summary {
		plan.stats.print(stderr)
	}

	return nil
}

func submitTargets(opts options, configTargets []target, stdin io.Reader, httpsURLs, httpURLs chan<- target, stderr io.Writer) {
	xlarge := []string{"81", "300", "591", "593", "832", "981", "1010", "1311", "2082", "2087", "2095", "2096", "2480", "3000", "3128", "3333", "4243", "4567", "4711", "4712", "4993", "5000", "5104", "5108", "5800", "6543", "7000", "7396", "7474", "8000", "8001", "8008", "8014", "8042", "8069", "8080", "8081", "8088", "8090", "8091", "8118", "8123", "8172", "8222", "8243", "8280", "8281", "8333", "8443", "8500", "8834", "8880", "8888", "8983", "9000", "9043", "9060", "9080", "9090", "9091", "9200", "9443", "9800", "9981", "12443", "16080", "18091", "18092", "20720", "28017"}
	large := []string{"81", "591", "2082", "2087", "2095", "2096", "3000", "8000", "8001", "8008", "8080", "8083", "8443", "8834", "8888"}

	submit := func(tgt target) {
		if !opts.skipDefault {
			httpsURLs <- tgt
		}

		for _, probe := range opts.probes {
			switch probe {
			case "xlarge":
				for _, port := range xlarge {
					httpsURLs <- target{host: tgt.host + ":" + port, rule: tgt.rule}
				}
			case "large":
				for _, port := range large {
					httpsURLs <- target{host: tgt.host + ":" + port, rule: tgt.rule}
				}
			default:
				pair := strings.SplitN(probe, ":", 2)
				if len(pair) != 2 {
					continue
				}

				probeTarget := target{host: tgt.host + ":" + pair[1], rule: tgt.rule}
				if strings.EqualFold(pair[0], "https") {
					httpsURLs <- probeTarget
				} else {
					httpURLs <- probeTarget
				}
			}
		}
	}

	for _, tgt := range configTargets {
		submit(tgt)
	}

	if shouldReadStdin(opts, len(configTargets), stdin) {
		sc := bufio.NewScanner(stdin)
		for sc.Scan() {
			submit(target{host: strings.ToLower(sc.Text())})
		}
		if err := sc.Err(); err != nil {
			fmt.Fprintf(stderr, "failed to read input: %s\n", err)
		}
	}
}

func shouldReadStdin(opts options, configTargetCount int, stdin io.Reader) bool {
	if opts.configPath == "" || configTargetCount == 0 {
		return true
	}

	file, ok := stdin.(*os.File)
	if !ok {
		return true
	}

	info, err := file.Stat()
	if err != nil {
		return true
	}
	return info.Mode()&os.ModeCharDevice == 0
}
