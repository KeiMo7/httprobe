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

## SARIF Output

To feed probe results into a security dashboard that consumes
[SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html),
enable SARIF output with the `-sarif` flag. Every listening service is written as
an independent result with a stable `ruleId`, a severity level, a message and the
precise location (line and columns) of the input entry that produced it. The
standard line-by-line stdout output is unchanged.

```
▶ cat domains.txt | httprobe -sarif results.sarif
```

By default results point at the `stdin` artifact. Pass `-input` to read domains
from a file instead; artifact locations are then stored repository-relative
(with a `%SRCROOT%` base id) so no absolute or temporary paths leak into the
report:

```
▶ httprobe -input recon/domains.txt -sarif results.sarif
```

Rules and levels are fixed across runs and versions:

| Rule ID | Meaning | Level |
| --- | --- | --- |
| `HTTPS-001` | HTTPS service listening on the default port (443) | `note` |
| `HTTP-001` | HTTP service listening on the default port (80) | `warning` |
| `PORT-001` | Service listening on a non-standard port | `error` |

The level mapping is defined in code in `sarif.go`; results are streamed and
flushed in chunks, so scans with tens of thousands of findings do not buffer the
entire report in memory. The file is written to a temporary path and atomically
renamed into place only after the document validates, so a failed scan never
leaves a half-written SARIF file. When the scan fails the report is still valid
and the single `invocation` is marked `executionSuccessful: false`.

## Docker

Build the docker container:

```
▶ docker build -t httprobe .
```

Run the container, passing the contents of a file into stdin of the process inside the container. `-i` is required to correctly map `stdin` into the container and to the `httprobe` binary.

```
▶ cat domains.txt | docker run -i httprobe <args>
```
