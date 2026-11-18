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

## Forward Proxies

httprobe can send HTTP requests in absolute-form and HTTPS requests through a
`CONNECT` tunnel. The target hostname is passed to the proxy; it is never
resolved locally just to select or reach the proxy.

### One proxy for every target

```
export CORP_PROXY_USER=probe
export CORP_PROXY_PASSWORD='read-from-your-secret-store'

cat domains.txt | httprobe \
  -proxy http://proxy.corp.example:3128 \
  -proxy-user-env CORP_PROXY_USER \
  -proxy-password-env CORP_PROXY_PASSWORD
```

The proxy address must include a port. Credentials are never accepted in the
`-proxy` URL or as literal command-line values. Use the two environment
variable *names* above, or the `username_env` / `password_env` fields in a
configuration file.

### Targets, CIDR routing and timeouts from a file

`-config` reads JSON without any additional dependencies. See
[`examples/proxy-config.json`](examples/proxy-config.json) for a complete file:

```json
{
  "targets": [
    "10.10.1.15",
    "10.20.30.40:8080",
    {"host": "legacy.intranet.example", "rule": "R1"}
  ],
  "proxies": [
    {"id": "P0", "address": "http://10.0.0.10:3128"},
    {
      "id": "P1",
      "address": "http://10.0.0.11:3128",
      "username_env": "PROXY_P1_USER",
      "password_env": "PROXY_P1_PASSWORD"
    }
  ],
  "rules": [
    {"id": "R0", "cidr": "10.10.0.0/16", "proxy_id": "P0"},
    {"id": "R2", "cidr": "10.10.1.0/24", "proxy_id": "P1"},
    {"id": "R1", "cidr": "10.20.0.0/16", "proxy_id": "P1"}
  ],
  "timeout_ms": 10000,
  "connect_timeout_ms": 2000,
  "read_timeout_ms": 5000,
  "proxy_failure_threshold": 5,
  "summary": true
}
```

Use it with:

```
export PROXY_P1_USER=probe
export PROXY_P1_PASSWORD='read-from-your-secret-store'
httprobe -config examples/proxy-config.json -p http:8080 -p https:8443
```

Configuration rules:

- A target can be a string or an object. String targets are hostnames, IPs or
  `host:port` values. An object with `rule` pins a hostname target to a rule.
  This is required when a hostname must use a CIDR rule, because httprobe does
  not resolve the hostname locally.
- `rules` are matched against literal IP targets. The longest matching prefix
  wins. For example, `10.10.1.15` selects `R2` in the example above.
- Targets that match no rule use a direct connection. A rule can also specify
  `"proxy_id": "direct"` explicitly.
- Rules with overlapping CIDRs of the same prefix length are rejected at
  startup because their ordering would be ambiguous.
- `default_proxy` optionally sends unmatched targets through a proxy. If it is
  omitted, unmatched targets are direct. `-proxy` is shorthand for one proxy
  used as the default for every target.
- Rule and proxy IDs are optional. They default to `R0`, `R1`, ... and `P0`,
  `P1`, ... in file order. The selected rule ID is included in result output.
- Proxy addresses are validated before probing starts. Errors include the
  proxy ID and any rules that reference it.
- `timeout_ms` is the overall request limit. `connect_timeout_ms` applies to
  dialing the proxy or target, and `read_timeout_ms` applies to waiting for
  response headers. If the latter two are omitted they inherit `-t` or
  `timeout_ms`.
- `proxy_failure_threshold` is the number of consecutive proxy-level failures
  that opens that proxy's circuit. Once open, remaining probes assigned to that
  proxy fail immediately with `PROXY_CIRCUIT_OPEN`.
- `summary` defaults to `true` when any proxy is configured. Use `-summary` to
  request it without a proxy, or `"summary": false` to disable it.

`-t`, `-connect-timeout`, `-read-timeout` and `-proxy-fail-threshold` are also
available when a full config file is not needed. Non-zero config values take
precedence over the command-line timeout/threshold flags.

### Proxy-mode output

When at least one proxy is configured, successful stdout lines keep their
protocol prefix and append the selected proxy and rule:

```
https://10.10.1.15:443	proxy=P1	rule=R2
http://127.0.0.1:8080	proxy=direct	rule=DIRECT
```

Per-probe failures are written to stderr with a stable code:

```
FAIL	code=PROXY_AUTH_REQUIRED	target=https://10.10.1.15:443	proxy=P1	rule=R2	detail="407 Proxy Authentication Required"
```

At the end of a proxy run, stderr contains one summary line per selected rule:

```
SUMMARY	rule=R2	cidr=10.10.1.0/24	proxy=P1	checks=12	ok=7	target_fail=2	proxy_fail=3	circuit_open=0
```

Without proxy configuration, result output is unchanged: successful URLs are
written to stdout exactly as before, failures are not emitted, and no summary
is printed unless `-summary` is explicitly requested.

### Failure codes

| Code | Meaning |
| --- | --- |
| `PROXY_CONNECT_REFUSED` | The TCP connection to the proxy was refused. |
| `PROXY_AUTH_REQUIRED` | The proxy returned HTTP 407. |
| `PROXY_BAD_GATEWAY` | The proxy returned HTTP 502, including a failed upstream CONNECT. |
| `PROXY_CONNECT_TIMEOUT` | Dialing the proxy exceeded the connect timeout. |
| `PROXY_READ_TIMEOUT` | The proxy did not return response headers within the read timeout. |
| `PROXY_DNS_ERROR` | The proxy hostname could not be resolved. |
| `PROXY_TLS_ERROR` | TLS negotiation with an HTTPS proxy failed. |
| `PROXY_CONNECT_ERROR` | Another proxy-path connection error occurred. |
| `PROXY_CIRCUIT_OPEN` | The proxy circuit is open after repeated failures. |
| `TARGET_INVALID` | The generated target URL or HTTP method is invalid. |
| `TARGET_CONNECT_REFUSED` | A direct connection to the target was refused. |
| `TARGET_TIMEOUT` | A direct target connection timed out. |
| `TARGET_DNS_ERROR` | A direct target hostname could not be resolved. |
| `TARGET_TLS_ERROR` | A direct TLS handshake failed. |
| `TARGET_UNREACHABLE` | Another direct target connection error occurred. |

HTTP 502 is intentionally classified as a proxy-level failure even when the
proxy could not reach the upstream target. This makes chain failures visible;
direct target failures remain in the `TARGET_*` namespace.

### Actual local test output

The integration tests start local proxies and targets. These are three actual
stderr samples from `go test -run TestProxyFailureTypesAreDistinct -v`:

```
FAIL	code=PROXY_CONNECT_REFUSED	target=http://target.invalid:80	proxy=P0	rule=DEFAULT	detail="Get \"http://target.invalid:80\": proxyconnect tcp: dial tcp 127.0.0.1:45165: connect: connection refused"
FAIL	code=PROXY_AUTH_REQUIRED	target=http://target.invalid:80	proxy=P0	rule=DEFAULT	detail="407 Proxy Authentication Required"
FAIL	code=PROXY_BAD_GATEWAY	target=http://target.invalid:80	proxy=P0	rule=DEFAULT	detail="502 Bad Gateway"
```

HTTPS still uses the existing `http.Transport` TLS client configuration after
the proxy tunnel is established. Proxy support does not add an alternative TLS
path or disable certificate handling at the proxy layer.

## Docker

Build the docker container:

```
▶ docker build -t httprobe .
```

Run the container, passing the contents of a file into stdin of the process inside the container. `-i` is required to correctly map `stdin` into the container and to the `httprobe` binary.

```
▶ cat domains.txt | docker run -i httprobe <args>
```

## Tests

```
go test -count=1 ./...
go test -race -count=1 ./...
```
