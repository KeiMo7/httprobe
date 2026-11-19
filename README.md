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

## Stable batches

`httprobe` is designed to be run over the same target list repeatedly and to
produce the same result set every time:

* Every scheduled target reaches a terminal state (`reachable`, `refused`,
  `timeout`, `error`, `canceled`, `skipped`). A target is never silently
  dropped, even when the concurrency limit is much smaller than the batch.
* Results are emitted in a deterministic order derived from the input order,
  so two runs can be diffed directly.
* Duplicate `host:port` probes within one run are merged, so a target is never
  probed twice.
* Timeouts and refusals are classified from the concrete connection error
  (deadline / `ECONNREFUSED`), not from elapsed time.

Additional optional flags:

```
-p             add probes as before
-t             timeout in milliseconds
-c             concurrency (always at least one worker)
-attempts N    try each target up to N times (default 1)
-prefer-https  skip HTTP when HTTPS already works
--json         emit {url,status,attempts,last_error} per target instead of bare URLs
-o FILE        write results to FILE atomically; completed results survive Ctrl-C
-progress      print batch progress to stderr
-i FILE        read domains from FILE instead of stdin
```

`-json` reports the attempt count and the final error class for every target,
for example:

```
{"url":"http://example.com","status":"reachable","attempts":1,"last_error":"none","reachable":true}
{"url":"http://example.com:8080","status":"refused","attempts":1,"last_error":"connection_refused","reachable":false}
```

Bare-URL stdout stays the default; only reachable URLs are printed, exactly as
before. Progress and diagnostics go to stderr.

## Docker

Build the docker container:

```
▶ docker build -t httprobe .
```

Run the container, passing the contents of a file into stdin of the process inside the container. `-i` is required to correctly map `stdin` into the container and to the `httprobe` binary.

```
▶ cat domains.txt | docker run -i httprobe <args>
```

