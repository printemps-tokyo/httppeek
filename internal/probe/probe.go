// Package probe holds the pure, testable core of httppeek: it follows an
// HTTP redirect chain by hand, classifies caching and security headers,
// summarizes TLS connection state, and records per-phase request timing.
//
// The functions here take standard-library values (an *http.Client, an
// http.Header, a *tls.ConnectionState) and return plain structs, so they can
// be exercised offline with net/http/httptest and crypto/tls.
package probe

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strings"
	"time"
)

// redirectCodes are the status codes httppeek treats as a redirect hop.
var redirectCodes = map[int]bool{
	http.StatusMovedPermanently:  true, // 301
	http.StatusFound:             true, // 302
	http.StatusSeeOther:          true, // 303
	http.StatusTemporaryRedirect: true, // 307
	http.StatusPermanentRedirect: true, // 308
}

// CachingHeaderNames lists the response headers httppeek highlights as
// caching-related, in display order.
var CachingHeaderNames = []string{
	"Cache-Control",
	"ETag",
	"Last-Modified",
	"Expires",
	"Age",
	"Vary",
	"Pragma",
}

// SecurityHeaderNames lists the response headers httppeek highlights as
// security-related, in display order.
var SecurityHeaderNames = []string{
	"Strict-Transport-Security",
	"Content-Security-Policy",
	"X-Content-Type-Options",
	"X-Frame-Options",
	"Referrer-Policy",
	"Permissions-Policy",
}

// Options configures a probe run.
type Options struct {
	Method       string        // GET (default) or HEAD
	Headers      []string      // extra request headers as "Key: Value"
	Timeout      time.Duration // overall per-request timeout
	Insecure     bool          // skip TLS certificate verification
	UserAgent    string        // User-Agent header value
	MaxRedirects int           // maximum redirect hops to follow
	NoFollow     bool          // report only the first response
}

// Hop is a single step in a redirect chain.
type Hop struct {
	Method     string `json:"method"`
	URL        string `json:"url"`
	StatusCode int    `json:"status_code"`
	Status     string `json:"status"`
	Location   string `json:"location,omitempty"`
	// SetCookie holds the hop's raw Set-Cookie values. They are not part of
	// the JSON output (cookie values can be secrets); see CollectCookies.
	SetCookie []string `json:"-"`
}

// HeaderKV is one response header rendered for display or JSON.
type HeaderKV struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// CertInfo summarizes a leaf certificate.
type CertInfo struct {
	Subject       string    `json:"subject"`
	Issuer        string    `json:"issuer"`
	NotBefore     time.Time `json:"not_before"`
	NotAfter      time.Time `json:"not_after"`
	DaysRemaining int       `json:"days_remaining"`
	DNSNames      []string  `json:"dns_names"`
}

// TLSInfo summarizes a negotiated TLS connection.
type TLSInfo struct {
	Version     string   `json:"version"`
	CipherSuite string   `json:"cipher_suite"`
	Cert        CertInfo `json:"certificate"`
}

// Timing holds best-effort per-phase durations for a single request.
type Timing struct {
	DNSLookup       time.Duration `json:"-"`
	TCPConnect      time.Duration `json:"-"`
	TLSHandshake    time.Duration `json:"-"`
	TimeToFirstByte time.Duration `json:"-"`
	Total           time.Duration `json:"-"`
}

// Final describes the terminal (non-redirect, or first when --no-follow)
// response of a probe.
type Final struct {
	URL        string
	StatusCode int
	Status     string
	Proto      string
	Headers    http.Header
}

// Result is the full outcome of a probe run.
type Result struct {
	RequestURL string
	Chain      []Hop
	Final      Final
	TLS        *TLSInfo
	Timing     Timing
	Cookies    []Cookie   // filled by CollectCookies
	HTTP3      *HTTP3Info // filled by CheckHTTP3
}

// ErrTooManyRedirects is returned when a chain exceeds Options.MaxRedirects.
var ErrTooManyRedirects = errors.New("too many redirects")

// ErrRedirectLoop is returned when a redirect target has already been visited.
var ErrRedirectLoop = errors.New("redirect loop detected")

// NewClient builds an *http.Client that never auto-follows redirects (so each
// hop can be reported) and that honors the timeout and insecure options.
func NewClient(opts Options) *http.Client {
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          10,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   opts.Timeout,
		ExpectContinueTimeout: time.Second,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: opts.Insecure, //nolint:gosec // opt-in via --insecure, warned to the user
		},
	}
	return &http.Client{
		Transport: transport,
		Timeout:   opts.Timeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// Run performs a probe: it follows the redirect chain of rawURL using client,
// records timing and TLS state for the final request, and returns a Result.
// rawURL must already carry a scheme (see NormalizeURL).
func Run(ctx context.Context, client *http.Client, rawURL string, opts Options) (*Result, error) {
	method := strings.ToUpper(strings.TrimSpace(opts.Method))
	if method == "" {
		method = http.MethodGet
	}

	result := &Result{RequestURL: rawURL}
	seen := map[string]bool{}
	currentURL := rawURL
	currentMethod := method

	for {
		if seen[currentMethod+" "+currentURL] {
			return result, fmt.Errorf("%w: %s", ErrRedirectLoop, currentURL)
		}
		seen[currentMethod+" "+currentURL] = true

		resp, timing, err := doRequest(ctx, client, currentMethod, currentURL, opts)
		if err != nil {
			return result, err
		}

		location := resp.Header.Get("Location")
		hop := Hop{
			Method:     currentMethod,
			URL:        currentURL,
			StatusCode: resp.StatusCode,
			Status:     resp.Status,
			Location:   location,
			SetCookie:  resp.Header.Values("Set-Cookie"),
		}
		result.Chain = append(result.Chain, hop)

		isRedirect := redirectCodes[resp.StatusCode] && location != ""

		if opts.NoFollow || !isRedirect {
			result.Final = Final{
				URL:        currentURL,
				StatusCode: resp.StatusCode,
				Status:     resp.Status,
				Proto:      resp.Proto,
				Headers:    resp.Header.Clone(),
			}
			result.Timing = timing
			if resp.TLS != nil {
				info := SummarizeTLS(resp.TLS)
				result.TLS = &info
			}
			resp.Body.Close()
			return result, nil
		}

		// Follow the redirect. Resolve Location against the current URL.
		next, resolveErr := resolveLocation(currentURL, location)
		resp.Body.Close()
		if resolveErr != nil {
			return result, resolveErr
		}

		if len(result.Chain) > opts.MaxRedirects {
			return result, fmt.Errorf("%w: exceeded --max-redirects=%d", ErrTooManyRedirects, opts.MaxRedirects)
		}

		currentMethod = nextMethod(currentMethod, resp.StatusCode)
		currentURL = next
	}
}

// doRequest issues one request with httptrace instrumentation and returns the
// response together with best-effort per-phase timing.
func doRequest(ctx context.Context, client *http.Client, method, rawURL string, opts Options) (*http.Response, Timing, error) {
	req, err := http.NewRequestWithContext(ctx, method, rawURL, nil)
	if err != nil {
		return nil, Timing{}, err
	}
	if opts.UserAgent != "" {
		req.Header.Set("User-Agent", opts.UserAgent)
	}
	for _, h := range opts.Headers {
		name, value, perr := ParseHeader(h)
		if perr != nil {
			return nil, Timing{}, perr
		}
		req.Header.Add(name, value)
	}

	var t Timing
	var start, dnsStart, connStart, tlsStart time.Time
	start = time.Now()
	trace := &httptrace.ClientTrace{
		DNSStart:     func(httptrace.DNSStartInfo) { dnsStart = time.Now() },
		DNSDone:      func(httptrace.DNSDoneInfo) { t.DNSLookup = time.Since(dnsStart) },
		ConnectStart: func(_, _ string) { connStart = time.Now() },
		ConnectDone: func(_, _ string, _ error) {
			if !connStart.IsZero() {
				t.TCPConnect = time.Since(connStart)
			}
		},
		TLSHandshakeStart: func() { tlsStart = time.Now() },
		TLSHandshakeDone: func(tls.ConnectionState, error) {
			if !tlsStart.IsZero() {
				t.TLSHandshake = time.Since(tlsStart)
			}
		},
		GotFirstResponseByte: func() { t.TimeToFirstByte = time.Since(start) },
	}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))

	resp, err := client.Do(req)
	t.Total = time.Since(start)
	if err != nil {
		return nil, t, err
	}
	return resp, t, nil
}

// nextMethod returns the request method to use when following a redirect.
// Per RFC 9110, 303 (and, in practice, 301/302 from non-idempotent methods)
// switch to GET; 307/308 preserve the method.
func nextMethod(method string, status int) string {
	switch status {
	case http.StatusSeeOther:
		return http.MethodGet
	case http.StatusMovedPermanently, http.StatusFound:
		if method != http.MethodGet && method != http.MethodHead {
			return http.MethodGet
		}
		return method
	default:
		return method
	}
}

// ClassifyHeaders extracts the caching and security headers present in h,
// preserving the documented display order and skipping absent headers.
func ClassifyHeaders(h http.Header) (caching, security []HeaderKV) {
	caching = pick(h, CachingHeaderNames)
	security = pick(h, SecurityHeaderNames)
	return caching, security
}

func pick(h http.Header, names []string) []HeaderKV {
	var out []HeaderKV
	for _, name := range names {
		if v := h.Get(name); v != "" {
			out = append(out, HeaderKV{Name: name, Value: v})
		}
	}
	return out
}

// AllHeaders returns every response header as a sorted slice of HeaderKV,
// joining multi-valued headers with ", ". Set-Cookie values are redacted
// (see RedactSetCookie): cookie values are often session secrets.
func AllHeaders(h http.Header) []HeaderKV {
	names := make([]string, 0, len(h))
	for name := range h {
		names = append(names, name)
	}
	sortStrings(names)
	out := make([]HeaderKV, 0, len(names))
	for _, name := range names {
		values := h.Values(name)
		if http.CanonicalHeaderKey(name) == "Set-Cookie" {
			redacted := make([]string, len(values))
			for i, v := range values {
				redacted[i] = RedactSetCookie(v)
			}
			values = redacted
		}
		out = append(out, HeaderKV{Name: name, Value: strings.Join(values, ", ")})
	}
	return out
}

// SummarizeTLS turns a tls.ConnectionState into a display-friendly TLSInfo.
func SummarizeTLS(cs *tls.ConnectionState) TLSInfo {
	info := TLSInfo{
		Version:     tls.VersionName(cs.Version),
		CipherSuite: tls.CipherSuiteName(cs.CipherSuite),
	}
	if len(cs.PeerCertificates) > 0 {
		leaf := cs.PeerCertificates[0]
		info.Cert = CertInfo{
			Subject:       leaf.Subject.String(),
			Issuer:        leaf.Issuer.String(),
			NotBefore:     leaf.NotBefore,
			NotAfter:      leaf.NotAfter,
			DaysRemaining: int(time.Until(leaf.NotAfter).Hours() / 24),
			DNSNames:      leaf.DNSNames,
		}
	}
	return info
}

// ExitCode maps a probe outcome to a process exit code:
//
//	2  the request errored (DNS, connection, TLS, timeout, ...)
//	1  the final response status is >= 400
//	0  a successful fetch with a final 2xx/3xx status
func ExitCode(statusCode int, err error) int {
	if err != nil {
		return 2
	}
	if statusCode >= 400 {
		return 1
	}
	return 0
}

// ParseHeader splits a "Key: Value" header specification. The value may be
// empty; leading/trailing spaces around the value are trimmed.
func ParseHeader(spec string) (name, value string, err error) {
	idx := strings.IndexByte(spec, ':')
	if idx <= 0 {
		return "", "", fmt.Errorf("invalid header %q: expected \"Key: Value\"", spec)
	}
	name = strings.TrimSpace(spec[:idx])
	value = strings.TrimSpace(spec[idx+1:])
	if name == "" {
		return "", "", fmt.Errorf("invalid header %q: empty name", spec)
	}
	return name, value, nil
}

// resolveLocation resolves a (possibly relative) Location header against the
// URL of the response that carried it.
func resolveLocation(base, location string) (string, error) {
	b, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	ref, err := url.Parse(location)
	if err != nil {
		return "", fmt.Errorf("invalid Location %q: %w", location, err)
	}
	return b.ResolveReference(ref).String(), nil
}

// NormalizeURL ensures the input carries a scheme, defaulting to https:// when
// none is present, and validates that it parses to an absolute http(s) URL.
func NormalizeURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("empty URL")
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("invalid URL %q: %w", raw, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("unsupported scheme %q: only http and https are supported", u.Scheme)
	}
	if u.Host == "" {
		return "", fmt.Errorf("invalid URL %q: missing host", raw)
	}
	return u.String(), nil
}

// sortStrings sorts a slice of header names case-insensitively but stably.
func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && strings.ToLower(s[j-1]) > strings.ToLower(s[j]); j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}

// RedactSetCookie replaces the value in a Set-Cookie line with its length,
// keeping the name and attributes: "sid=abc; Path=/" -> "sid=<3 bytes>; Path=/".
func RedactSetCookie(line string) string {
	pair, attrs, hasAttrs := strings.Cut(line, ";")
	name, value, ok := strings.Cut(pair, "=")
	if !ok {
		name, value = "", pair
	}
	out := fmt.Sprintf("<%d bytes>", len(strings.Trim(value, " \t")))
	if ok {
		out = strings.TrimSpace(name) + "=" + out
	}
	if hasAttrs {
		out += ";" + attrs
	}
	return out
}
