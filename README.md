# httppeek

> Follow a URL's redirect chain and read its final status, headers, cookies, TLS, HTTP/3 advertisement, and timing in one command, or compare several URLs side by side. Zero-dependency Go CLI.

[![CI](https://github.com/printemps-tokyo/httppeek/actions/workflows/ci.yml/badge.svg)](https://github.com/printemps-tokyo/httppeek/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](./LICENSE)

`curl -IL` shows you a URL's headers; `httppeek` lays out the whole request in
one view: every redirect hop, the final status, the caching and security
headers that actually matter, every cookie the chain sets (checked against the
rules browsers apply), the negotiated TLS and certificate, whether the host
advertises HTTP/3, and where the time went. Give it several URLs and it fetches
them in parallel and prints a comparison. It is a read-only diagnostic client:
the only network traffic is the requests to the URLs you name and a DNS query
for their HTTPS records.

```console
$ httppeek --method HEAD --dns 1.1.1.1 http://github.com
URL: http://github.com

Redirect chain
  1. HEAD http://github.com
     301 Moved Permanently
     -> Location: https://github.com/
  2. HEAD https://github.com/
     200 OK

Final response
  https://github.com/
  HTTP/2.0 200 OK

Caching headers
  Cache-Control: max-age=0, private, must-revalidate
  ETag: W/"c14005aa4607d2c03144b0845852d77a"
  Vary: Accept-Encoding, Accept, X-Requested-With

Security headers
  Strict-Transport-Security: max-age=31536000; includeSubdomains; preload
  Content-Security-Policy: default-src 'none'; base-uri 'self'; ...
  X-Content-Type-Options: nosniff
  X-Frame-Options: deny
  Referrer-Policy: origin-when-cross-origin, strict-origin-when-cross-origin

All response headers
  Accept-Ranges: bytes
  Cache-Control: max-age=0, private, must-revalidate
  ...

Cookies
  _gh_sess  (hop 2, value 358 bytes)
    Path=/; session; Secure; HttpOnly; SameSite=Lax
  _octo  (hop 2, value 27 bytes)
    Domain=github.com; Path=/; Expires=Fri, 12 Nov 2027 06:31:30 GMT; Secure; SameSite=Lax
    warning:  no HttpOnly: readable by page scripts
  logged_in  (hop 2, value 2 bytes)
    Domain=github.com; Path=/; Expires=Fri, 12 Nov 2027 06:31:30 GMT; Secure; HttpOnly; SameSite=Lax

TLS
  Version:      TLS 1.3
  Cipher suite: TLS_AES_128_GCM_SHA256
  Subject:      CN=github.com
  Issuer:       CN=Sectigo ECC Domain Validation Secure Server CA,O=Sectigo Limited,C=GB
  Valid:        2026-02-05 -> 2027-02-05 (201 days remaining)
  SANs:         github.com, www.github.com

HTTP/3 (advertised; httppeek does not connect over QUIC)
  Advertised:  no
  Alt-Svc:     (none)
  HTTPS RR:    (none, via 1.1.1.1:53)

Timing (final request)
  DNS lookup:          9ms
  TCP connect:         6ms
  TLS handshake:       18ms
  Time to first byte:  43ms
  Total:               43ms
```

## Requirements

- Go >= 1.23 (only to build or `go install`; prebuilt binaries arrive with
  tagged releases)

## Install

```bash
go install github.com/printemps-tokyo/httppeek@latest
```

This puts a `httppeek` binary in `$(go env GOPATH)/bin`. Prebuilt binaries for
linux and darwin (amd64 and arm64) are attached to each tagged release once the
project starts cutting them.

Or build from a clone:

```bash
git clone https://github.com/printemps-tokyo/httppeek
cd httppeek
go build -o httppeek .
./httppeek example.com
```

## Usage

```bash
httppeek example.com                       # scheme defaults to https://
httppeek https://example.com/path          # explicit scheme and path
httppeek --method HEAD example.com         # HEAD instead of GET
httppeek --no-follow example.com           # show only the first response
httppeek --header "Accept: application/json" api.example.com
httppeek --json example.com                # machine-readable output
httppeek --insecure https://self-signed.local   # skip TLS verification
httppeek example.com www.example.com            # compare several URLs
httppeek --full a.example b.example             # comparison plus each full report
httppeek --dns 1.1.1.1 example.com              # pick the DNS server for the HTTPS record
```

| Option | Description |
| --- | --- |
| `<url>...` | One or more URLs to fetch. The scheme may be omitted; `https://` is assumed. Several URLs are fetched in parallel (up to 4 at a time) and compared. |
| `--method <m>` | Request method: `GET` (default) or `HEAD`. |
| `--header "K: V"` | Add a request header. Repeatable. |
| `--timeout <dur>` | Per-request timeout (default `10s`), e.g. `5s`, `1500ms`. |
| `--max-redirects <n>` | Maximum redirect hops to follow (default `10`). Exceeding it is an error. |
| `--no-follow` | Report only the first response; do not follow redirects. |
| `--insecure` | Skip TLS certificate verification. Prints a warning to stderr. |
| `--user-agent <ua>` | Set the `User-Agent` header (default `httppeek/<version>`). |
| `--dns <server>` | DNS server for the HTTPS record lookup, as `ip`, `ip:port`, or `[ipv6]:port` (default: the first `nameserver` in `/etc/resolv.conf`; none on Windows). |
| `--no-dns` | Skip the HTTPS record lookup; HTTP/3 is then judged from `Alt-Svc` alone. |
| `--full` | With several URLs, print each full report after the comparison. |
| `--json` | Emit structured JSON instead of text: one object for one URL, an array for several. |
| `--version` | Print the version and exit. |
| `--help` | Show help and exit. |

Redirects are followed by hand (not by the HTTP client's auto-follow) so each
hop can be reported. A redirect target that has already been visited is
reported as a loop, and exceeding `--max-redirects` is a clear error.

## Exit codes

httppeek is built for CI and monitoring crons. With several URLs the exit code
is the highest of them:

| Code | Meaning |
| --- | --- |
| `0` | Successful fetch with a final `2xx` or `3xx` status. |
| `1` | The final response status is `>= 400`. |
| `2` | The request errored (DNS, connection, TLS, timeout) or arguments were invalid. |

## JSON schema

`--json` prints one object with a stable shape:

```jsonc
{
  "request_url": "https://example.com",        // URL as normalized and requested
  "chain": [                                    // one entry per hop, in order
    {
      "method": "GET",
      "url": "https://example.com",
      "status_code": 200,
      "status": "200 OK",
      "location": "https://..."                 // present only on redirect hops
    }
  ],
  "final": {
    "url": "https://example.com",
    "status_code": 200,
    "status": "200 OK",
    "proto": "HTTP/2.0",
    "caching_headers":  [ { "name": "Cache-Control", "value": "max-age=0" } ],
    "security_headers": [ { "name": "Strict-Transport-Security", "value": "..." } ],
    "headers":          [ { "name": "Content-Type", "value": "text/html" } ]
  },
  "tls": {                                       // null for plain http
    "version": "TLS 1.3",
    "cipher_suite": "TLS_AES_128_GCM_SHA256",
    "certificate": {
      "subject": "CN=example.com",
      "issuer": "CN=...",
      "not_before": "2026-05-31T00:00:00Z",
      "not_after": "2026-08-29T23:59:59Z",
      "days_remaining": 41,
      "dns_names": ["example.com", "*.example.com"]
    }
  },
  "timing": {                                    // milliseconds, best-effort
    "dns_lookup_ms": 9,
    "tcp_connect_ms": 6,
    "tls_handshake_ms": 18,
    "time_to_first_byte_ms": 43,
    "total_ms": 43
  },
  "cookies": [                                   // every Set-Cookie in the chain
    {
      "hop": 1,                                  // 1-based index into chain
      "name": "sid",
      "value_bytes": 32,                         // the value itself is never output
      "domain": "example.com",                   // present when set
      "path": "/",
      "expires": "Wed, 01 Jan 2031 00:00:00 GMT", // or "max_age": 3600
      "secure": true,
      "http_only": true,
      "same_site": "Lax",                        // as written; omitted when absent
      "partitioned": false,
      "rejected": [],                            // why a browser would ignore it
      "warnings": ["lifetime over 400 days: browsers cut it to 400"]
    }
  ],
  "http3": {
    "alt_svc": [ { "protocol": "h3", "authority": ":443", "max_age": 86400 } ],
    "alt_svc_clear": false,
    "query_name": "example.com",                 // omitted when not looked up
    "aliases": [],                               // AliasMode targets followed
    "https_records": [ { "priority": 1, "target": ".", "alpn": ["h3", "h2"], "no_default_alpn": false } ],
    "dns_server": "1.1.1.1:53",                  // omitted when not looked up
    "dns_error": "...",                          // present only when the lookup failed
    "advertised": true
  },
  "exit_code": 0
}
```

`chain`, `caching_headers`, `security_headers`, `headers`, `cookies`, and the
lists inside `http3` are always arrays (never `null`). `tls` is `null` for
`http://` URLs. With several URLs the output is an array with one such object
per URL, in argument order; a URL whose request failed appears as
`{ "request_url": "...", "error": "...", "exit_code": 2 }`.

## What it reports

- Redirect chain: for every hop, the method, request URL, status code and text,
  and the `Location` header, stopping at the final non-redirect response.
- Caching headers: `Cache-Control`, `ETag`, `Last-Modified`, `Expires`, `Age`,
  `Vary`, `Pragma`.
- Security headers: `Strict-Transport-Security`, `Content-Security-Policy`,
  `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`,
  `Permissions-Policy`.
- All response headers, sorted, in a full section.
- TLS (https only): negotiated version and cipher suite, and the leaf
  certificate's subject, issuer, validity window with days remaining, and SANs.
- Timing for the final request: DNS lookup, TCP connect, TLS handshake, and
  time to first byte, measured with `net/http/httptrace`.
- Cookies: every `Set-Cookie` on every hop, with its attributes and the value's
  length (never the value). Each is checked against the storage model of
  [RFC 6265bis](https://datatracker.ietf.org/doc/draft-ietf-httpbis-rfc6265bis/)
  (draft 22). Rejected, meaning a browser ignores the cookie: a name and value
  over 4096 bytes together, a control character in either, `Secure` set over
  plain http, `SameSite=None` without `Secure`, a `__Secure-` name without
  `Secure`, a `__Host-` name without `Secure`, with a `Domain`, or without a
  `Path` that works out to `/` (prefixes match case-insensitively), a nameless
  cookie whose value starts with one of those prefixes, and a `Domain` that
  does not cover the host. Warnings: no `Secure` on an https site, no `HttpOnly`, no
  `SameSite` (the browser default applies), a `SameSite` value other than
  Strict, Lax, or None, and a lifetime over the 400 days the draft tells
  browsers to cap at.
- HTTP/3: whether the final host advertises it, from the `Alt-Svc` header
  ([RFC 7838](https://www.rfc-editor.org/rfc/rfc7838)) and from the host's
  DNS HTTPS record ([RFC 9460](https://www.rfc-editor.org/rfc/rfc9460)), whose
  `alpn` list a browser reads before its first connection. The record is
  looked up under the name RFC 9460 Section 9.1 gives (the host on port 443,
  `_PORT._https.host` otherwise, with `http://` treated as `https://`),
  AliasMode records are followed (up to 8, with loop detection), and an RRset
  with a malformed record is reported and ignored, as the RFC tells clients
  to. httppeek does not speak QUIC, so this is what the host announces, not a
  test of HTTP/3 itself.
  The DNS query is a small UDP query (TCP when the answer is truncated) of its
  own, since Go's resolver has no HTTPS record lookup.
- Comparison (several URLs): one row per URL with status, redirect hops,
  protocol, TLS version, certificate days left, HTTP/3, cookie count (and how
  many a browser would reject), and total time, then the final URLs, then each
  of `Content-Type`, `Server`, and the caching and security headers whose
  values differ between the URLs.

## Security and privacy

httppeek is a user-invoked diagnostic client. It sends requests only to the
URLs you name, plus one DNS query per final host for its HTTPS record (to the
system's resolver or `--dns`; skip it with `--no-dns`). It adds no analytics
and reports nowhere else. Cookie values are never printed: the cookie report
shows their length, and `Set-Cookie` in the full header list shows
`name=<N bytes>` followed by the attributes. `--insecure` disables TLS
certificate verification for the connection and prints a warning to stderr; use
it only against hosts you control.

## Design

The redirect-follow, header-classification, cookie, HTTP/3, TLS-summary, and
timing logic lives in the `internal/probe` package as pure functions over standard-library types
(`*http.Client`, `http.Header`, `*tls.ConnectionState`), so it is unit-tested
offline with `net/http/httptest`. `main.go` handles argument parsing, wiring,
and output. There are no third-party dependencies: httppeek is standard-library
only.

## License

[MIT](./LICENSE) (c) printemps.tokyo
