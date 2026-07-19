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
	if cfg.url != "example.com" {
		t.Errorf("url: got %q", cfg.url)
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
		{"a.com", "b.com"},
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
