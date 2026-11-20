# httprobe

Take a list of domains and probe for working http and https servers.

## Install

```
▶ go install github.com/tomnomnom/httprobe@latest
```

## Basic Usage

httprobe accepts line-delimited domains on `stdin`:

```
▶ cat recon/example/domains.txt
example.com
example.edu
example.net
▶ cat recon/example/domains.txt | httprobe
http://example.com
http://example.net
http://example.edu
https://example.com
https://example.edu
https://example.net
```

## Extra Probes

By default httprobe checks for HTTP on port 80 and HTTPS on port 443. You can add additional
probes with the `-p` flag by specifying a protocol and port pair:

```
▶ cat domains.txt | httprobe -p http:81 -p https:8443
```

## Concurrency

You can set the concurrency level with the `-c` flag:

```
▶ cat domains.txt | httprobe -c 50
```

## Timeout

You can change the timeout by using the `-t` flag and specifying a timeout in milliseconds:

```
▶ cat domains.txt | httprobe -t 20000
```

## Skipping Default Probes

If you don't want to probe for HTTP on port 80 or HTTPS on port 443, you can use the
`-s` flag. You'll need to specify the probes you do want using the `-p` flag:

```
▶ cat domains.txt | httprobe -s -p https:8443
```

## Prefer HTTPS

Sometimes you don't care about checking HTTP if HTTPS is working. You can do that with the `--prefer-https` flag:

```
▶ cat domains.txt | httprobe --prefer-https
```

## Input Normalization And Trace Output

Input lines are normalized before probing, so the same host written in
different ways is only probed once. Normalization is purely string/encoding
work — no DNS lookups are performed — and is idempotent:

* `http://` / `https://` prefixes are accepted in any case and stripped from
  the probe target (the original spelling is kept in the trace).
* Host names are lower-cased and a trailing dot is removed.
* Internationalized domain names are converted to punycode (e.g.
  `bücher.example` → `xn--bcher-kva.example`); the raw line is preserved in
  the trace. A line that cannot be converted is skipped and reported instead
  of being silently rewritten.
* The path, query string and fragment are stripped from the probe target but
  retained in the trace.
* IPv6 literals are accepted with or without brackets and canonicalized to
  the bracketed form (`[2001:db8::1]`, `[2001:db8::1]:8443`) so the host/port
  boundary is always unambiguous.
* Surrounding spaces, tabs and carriage returns are trimmed; blank lines are
  skipped. Lines that cannot be parsed (e.g. `:8080`, `https://`, a bad port)
  are counted on stderr and skipped without aborting the batch.

Use `-trace` to write the mapping between each probe target and every raw
input line that produced it as JSON Lines. Trace data never goes to stdout,
which keeps its one-result-per-line contract:

```
▶ cat domains.txt | httprobe -trace trace.jsonl
▶ cat domains.txt | httprobe -trace -   # write the trace to stderr
```

A failure to open or write the trace file is reported on stderr; probing
continues without the trace.

## Docker

Build the docker container:

```
▶ docker build -t httprobe .
```

Run the container, passing the contents of a file into stdin of the process inside the container. `-i` is required to correctly map `stdin` into the container and to the `httprobe` binary.

```
▶ cat domains.txt | docker run -i httprobe <args>
```

