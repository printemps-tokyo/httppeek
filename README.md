# httppeek

> Follow a URL's redirect chain and read its final status, headers, TLS, and timing in one command. Zero-dependency Go CLI.

[![CI](https://github.com/printemps-tokyo/httppeek/actions/workflows/ci.yml/badge.svg)](https://github.com/printemps-tokyo/httppeek/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](./LICENSE)

`curl -IL` shows you a URL's headers; `httppeek` lays out the whole request in
one view: every redirect hop, the final status, the caching and security
headers that actually matter, the negotiated TLS and certificate, and where the
time went. It is a read-only diagnostic client, and the only network traffic is
the requests to the URL you name.

```console
$ httppeek --method HEAD http://github.com
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

TLS
  Version:      TLS 1.3
  Cipher suite: TLS_AES_128_GCM_SHA256
  Subject:      CN=github.com
  Issuer:       CN=Sectigo ECC Domain Validation Secure Server CA,O=Sectigo Limited,C=GB
  Valid:        2026-02-05 -> 2027-02-05 (201 days remaining)
  SANs:         github.com, www.github.com

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
```

| Option | Description |
| --- | --- |
| `<url>` | URL to fetch. The scheme may be omitted; `https://` is assumed. |
| `--method <m>` | Request method: `GET` (default) or `HEAD`. |
| `--header "K: V"` | Add a request header. Repeatable. |
| `--timeout <dur>` | Per-request timeout (default `10s`), e.g. `5s`, `1500ms`. |
| `--max-redirects <n>` | Maximum redirect hops to follow (default `10`). Exceeding it is an error. |
| `--no-follow` | Report only the first response; do not follow redirects. |
| `--insecure` | Skip TLS certificate verification. Prints a warning to stderr. |
| `--user-agent <ua>` | Set the `User-Agent` header (default `httppeek/<version>`). |
| `--json` | Emit structured JSON instead of text. |
| `--version` | Print the version and exit. |
| `--help` | Show help and exit. |

Redirects are followed by hand (not by the HTTP client's auto-follow) so each
hop can be reported. A redirect target that has already been visited is
reported as a loop, and exceeding `--max-redirects` is a clear error.

## Exit codes

httppeek is built for CI and monitoring crons:

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
  "exit_code": 0
}
```

`chain`, `caching_headers`, `security_headers`, and `headers` are always arrays
(never `null`). `tls` is `null` for `http://` URLs.

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

## Security and privacy

httppeek is a user-invoked diagnostic client. It sends requests only to the URL
you name, adds no analytics, and reports nowhere else. `--insecure` disables TLS
certificate verification for the connection and prints a warning to stderr; use
it only against hosts you control.

## Design

The redirect-follow, header-classification, TLS-summary, and timing logic lives
in the `internal/probe` package as pure functions over standard-library types
(`*http.Client`, `http.Header`, `*tls.ConnectionState`), so it is unit-tested
offline with `net/http/httptest`. `main.go` handles argument parsing, wiring,
and output. There are no third-party dependencies: httppeek is standard-library
only.

## License

[MIT](./LICENSE) (c) printemps.tokyo
