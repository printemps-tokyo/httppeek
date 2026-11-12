package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestParseArgsDefaults(t *testing.T) {
	cfg, err := parseArgs([]string{"example.com"})
	if err != nil {
		t.Fatalf("parseArgs: %v", err)
	}
	if len(cfg.urls) != 1 || cfg.urls[0] != "example.com" {
		t.Errorf("urls: got %q", cfg.urls)
	}
	if cfg.opts.Method != "GET" {
		t.Errorf("default method: got %q", cfg.opts.Method)
	}
	if cfg.opts.Timeout != 10*time.Second {
		t.Errorf("default timeout: got %v", cfg.opts.Timeout)
	}
	if cfg.opts.MaxRedirects != 10 {
		t.Errorf("default max-redirects: got %d", cfg.opts.MaxRedirects)
	}
}

func TestParseArgsRepeatableHeader(t *testing.T) {
	cfg, err := parseArgs([]string{"--header", "A: 1", "--header=B: 2", "example.com"})
	if err != nil {
		t.Fatalf("parseArgs: %v", err)
	}
	if len(cfg.opts.Headers) != 2 {
		t.Fatalf("want 2 headers, got %d: %+v", len(cfg.opts.Headers), cfg.opts.Headers)
	}
	if cfg.opts.Headers[0] != "A: 1" || cfg.opts.Headers[1] != "B: 2" {
		t.Errorf("headers wrong: %+v", cfg.opts.Headers)
	}
}

func TestParseArgsSchemeAndFlags(t *testing.T) {
	cfg, err := parseArgs([]string{"--method", "HEAD", "--no-follow", "--insecure", "--json", "--max-redirects=3", "http://x"})
	if err != nil {
		t.Fatalf("parseArgs: %v", err)
	}
	if cfg.opts.Method != "HEAD" || !cfg.opts.NoFollow || !cfg.opts.Insecure || !cfg.jsonOut {
		t.Errorf("flags not applied: %+v json=%v", cfg.opts, cfg.jsonOut)
	}
	if cfg.opts.MaxRedirects != 3 {
		t.Errorf("max-redirects: got %d", cfg.opts.MaxRedirects)
	}
}

func TestParseArgsBadInputs(t *testing.T) {
	cases := [][]string{
		{"--timeout", "notaduration", "example.com"},
		{"--timeout", "-5s", "example.com"},
		{"--method", "POST", "example.com"},
		{"--max-redirects", "-1", "example.com"},
		{"--unknown"},
		{"--timeout"},
		{"--dns", "1.1.1.1", "--no-dns", "a.com"},
		{"--dns=", "a.com"},
		{"--dns", "host:", "a.com"},
	}
	for _, args := range cases {
		if _, err := parseArgs(args); err == nil {
			t.Errorf("parseArgs(%v): expected error", args)
		}
	}
}

func TestRunHelpAndVersion(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"--help"}, &out, &errb); code != 0 {
		t.Errorf("--help exit code: got %d", code)
	}
	if !strings.Contains(out.String(), "Usage:") {
		t.Errorf("--help output missing usage")
	}

	out.Reset()
	if code := run([]string{"--version"}, &out, &errb); code != 0 {
		t.Errorf("--version exit code: got %d", code)
	}
	if !strings.Contains(out.String(), "httppeek") {
		t.Errorf("--version output missing name")
	}
}

func TestRunEndToEndExitCodes(t *testing.T) {
	okSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Cache-Control", "max-age=0")
		w.WriteHeader(http.StatusOK)
	}))
	defer okSrv.Close()

	notFoundSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer notFoundSrv.Close()

	var out, errb bytes.Buffer
	if code := run([]string{okSrv.URL}, &out, &errb); code != 0 {
		t.Errorf("2xx should exit 0, got %d (stderr: %s)", code, errb.String())
	}
	if !strings.Contains(out.String(), "Final response") {
		t.Errorf("text output missing 'Final response': %s", out.String())
	}

	out.Reset()
	errb.Reset()
	if code := run([]string{notFoundSrv.URL}, &out, &errb); code != 1 {
		t.Errorf("404 should exit 1, got %d", code)
	}
}

func TestRunJSONOutput(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	var out, errb bytes.Buffer
	if code := run([]string{"--json", srv.URL}, &out, &errb); code != 0 {
		t.Fatalf("exit code: got %d", code)
	}
	s := out.String()
	if !strings.Contains(s, `"request_url"`) || !strings.Contains(s, `"timing"`) {
		t.Errorf("JSON output missing expected keys: %s", s)
	}
}

func TestRunBadURLExit2(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"ftp://example.com"}, &out, &errb); code != 2 {
		t.Errorf("unsupported scheme should exit 2, got %d", code)
	}
}

func TestParseArgsSeveralURLsAndDNS(t *testing.T) {
	cfg, err := parseArgs([]string{"a.com", "--dns", "9.9.9.9", "b.com", "--full"})
	if err != nil {
		t.Fatalf("parseArgs: %v", err)
	}
	if len(cfg.urls) != 2 || cfg.urls[1] != "b.com" || !cfg.full {
		t.Errorf("got %+v", cfg)
	}
	if cfg.dnsServer != "9.9.9.9:53" {
		t.Errorf("dns: got %q", cfg.dnsServer)
	}
	for in, want := range map[string]string{
		"1.1.1.1":              "1.1.1.1:53",
		"1.1.1.1:5353":         "1.1.1.1:5353",
		"2606:4700::1111":      "[2606:4700::1111]:53",
		"[2606:4700::1111]:53": "[2606:4700::1111]:53",
		"dns.example:53":       "dns.example:53",
	} {
		got, err := dnsAddress(in)
		if err != nil || got != want {
			t.Errorf("dnsAddress(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
}

func TestRunComparesSeveralURLs(t *testing.T) {
	a := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Cache-Control", "max-age=60")
		w.Header().Add("Set-Cookie", "sid=secret-value; Path=/; HttpOnly")
		w.Header().Set("Alt-Svc", `h3=":443"; ma=86400`)
		w.WriteHeader(http.StatusOK)
	}))
	defer a.Close()
	b := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusNotFound)
	}))
	defer b.Close()

	var out, errb bytes.Buffer
	code := run([]string{"--no-dns", a.URL, b.URL}, &out, &errb)
	if code != 1 {
		t.Errorf("worst exit code should be 1, got %d (stderr %s)", code, errb.String())
	}
	s := out.String()
	for _, want := range []string{"Comparison", "Header differences", "Cache-Control", "max-age=60", "no-store", "yes"} {
		if !strings.Contains(s, want) {
			t.Errorf("comparison missing %q:\n%s", want, s)
		}
	}
	if strings.Contains(s, "secret-value") {
		t.Errorf("cookie value leaked into the comparison:\n%s", s)
	}

	out.Reset()
	if code := run([]string{"--no-dns", "--json", a.URL, b.URL}, &out, &errb); code != 1 {
		t.Errorf("json exit code: got %d", code)
	}
	if !strings.HasPrefix(strings.TrimSpace(out.String()), "[") {
		t.Errorf("several URLs should give a JSON array: %s", out.String())
	}
	if strings.Contains(out.String(), "secret-value") {
		t.Errorf("cookie value leaked into JSON")
	}
}

func TestRunReportsCookiesAndHTTP3(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Add("Set-Cookie", "__Host-id=abc; Secure; Path=/")
		w.Header().Set("Alt-Svc", `h3=":443"; ma=3600, h2=":443"`)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	var out, errb bytes.Buffer
	if code := run([]string{"--no-dns", srv.URL}, &out, &errb); code != 0 {
		t.Fatalf("exit code %d: %s", code, errb.String())
	}
	s := out.String()
	for _, want := range []string{
		"Cookies",
		"__Host-id  (hop 1, value 3 bytes)",
		"rejected: Secure cookie set over plain http",
		"__Host-id=<3 bytes>; Secure; Path=/",
		"HTTP/3 (advertised",
		"Advertised:  yes",
		`h3=":443" ma=3600`,
		"HTTPS RR:    (not looked up)",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("output missing %q:\n%s", want, s)
		}
	}
	if strings.Contains(s, "=abc") {
		t.Errorf("cookie value leaked:\n%s", s)
	}
}

func TestShorten(t *testing.T) {
	if shorten("") != "(absent)" || shorten("abc") != "abc" {
		t.Error("short values")
	}
	long := strings.Repeat("x", 130)
	if got := shorten(long); got != strings.Repeat("x", 117)+"... (130 chars)" {
		t.Errorf("got %q", got)
	}
}
