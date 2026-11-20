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

## Failure Classification And Retries

By default httprobe prints only working targets, one per line, exactly as it
always has. Enabling the diagnostics channel adds a separate, machine-readable
record of what happened to *every* target — the working-target output on
stdout is unchanged and stays consumable by existing downstream tooling.

```
▶ cat domains.txt | httprobe -diag diagnostics.jsonl
http://example.com
▶ cat diagnostics.jsonl
{"target":"http://example.com","category":"available","retries":0}
{"target":"http://example.edu","category":"connection_refused","retries":0,"error":"dial tcp ...: connect: connection refused"}
```

Use `-diag -` to send the diagnostics stream to stderr instead of a file.
The two streams are always independent: nothing diagnostic is ever written to
stdout, and if the diagnostics destination cannot be written to, the sink is
disabled for the rest of the run and probing continues uninterrupted.

### Categories

Classification is derived solely from observable failure signals (DNS errors,
TCP refusal, timeouts at the connect/read phases, TLS alerts and certificate
verification results) — never from elapsed-time guessing, so the same input
repeatedly yields the same category.

| Category              | Meaning                                                            | Retried |
|-----------------------|--------------------------------------------------------------------|---------|
| `available`           | a complete HTTP response was received                              | —       |
| `connect_timeout`     | no response to the connection handshake; connect budget exhausted  | yes     |
| `read_timeout`        | connected, but no TLS handshake / response headers before budget   | yes     |
| `tls_protocol`        | reachable, but TLS negotiation rejected (version/cipher mismatch)  | no      |
| `tls_certificate`     | TLS completed, but certificate chain verification failed           | no      |
| `connection_refused`  | the peer explicitly rejected the connection (deterministic)        | no      |
| `dns_error`           | name resolution failed — a local-side problem, not remote downtime | no      |
| `unknown`             | no signal matched (e.g. disconnect mid-negotiation); raw error kept| no      |

Only `connect_timeout` and `read_timeout` are retryable. A target is retried at
most `--retries` times (default 1) for the same category within one run; the
verdict always records the category of the final attempt together with the
retry count. A deterministic conclusion is returned immediately and can never
be downgraded to `unknown` by a retry. A target that fails once on a retryable
category and then succeeds is emitted exactly once as `available`, carrying the
number of retries it took.

### Time Budgets

`-t` sets the independent budget for each of the two probe phases: establishing
the connection (including DNS), and reading the post-connect response (TLS
handshake plus HTTP headers). The total wall-clock time spent on one target is
capped at `(retries+1)` times the two phase budgets regardless of how many
attempts run, so retries cannot multiply the budget without bound.

### Deduplication

Each fully-qualified `scheme://host:port` target is probed at most once per run
even if it is enqueued repeatedly (duplicate input lines, overlapping default
and additional probes). The same host reached on different ports are distinct
targets and their verdicts never overwrite each other. HTTPS is always
attempted before the plaintext HTTP fallback, in the same order as before.

With `-diag` unset, none of this machinery is active: the program follows its
original single-pass, no-retry behavior.

## Docker

Build the docker container:

```
▶ docker build -t httprobe .
```

Run the container, passing the contents of a file into stdin of the process inside the container. `-i` is required to correctly map `stdin` into the container and to the `httprobe` binary.

```
▶ cat domains.txt | docker run -i httprobe <args>
```

