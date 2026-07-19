package probe

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func defaultOpts() Options {
	return Options{
		Method:       "GET",
		Timeout:      5 * time.Second,
		MaxRedirects: 10,
		UserAgent:    "httppeek-test",
	}
}

func TestRunRedirectChain(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/one", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/two", http.StatusMovedPermanently) // 301
	})
	mux.HandleFunc("/two", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/three", http.StatusFound) // 302
	})
	mux.HandleFunc("/three", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK) // 200
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	res, err := Run(context.Background(), NewClient(defaultOpts()), srv.URL+"/one", defaultOpts())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(res.Chain) != 3 {
		t.Fatalf("want 3 hops, got %d: %+v", len(res.Chain), res.Chain)
	}
	wantCodes := []int{301, 302, 200}
	for i, code := range wantCodes {
		if res.Chain[i].StatusCode != code {
			t.Errorf("hop %d: want %d, got %d", i, code, res.Chain[i].StatusCode)
		}
	}
	if res.Chain[0].Location == "" || res.Chain[1].Location == "" {
		t.Errorf("redirect hops should carry a Location header: %+v", res.Chain)
	}
	if res.Final.StatusCode != 200 {
		t.Errorf("final status: want 200, got %d", res.Final.StatusCode)
	}
}

func TestRunMaxRedirectsExceeded(t *testing.T) {
	// A server that redirects forever to a fresh path so no loop is detected
	// before the cap is hit.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, r.URL.Path+"x", http.StatusFound)
	}))
	defer srv.Close()

	opts := defaultOpts()
	opts.MaxRedirects = 3
	_, err := Run(context.Background(), NewClient(opts), srv.URL+"/a", opts)
	if err == nil {
		t.Fatal("expected an error when max redirects exceeded")
	}
	if !errors.Is(err, ErrTooManyRedirects) {
		t.Errorf("want ErrTooManyRedirects, got %v", err)
	}
}

func TestRunRedirectLoop(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// /loop always points back to /loop -> same method+URL revisited.
		http.Redirect(w, r, "/loop", http.StatusFound)
	}))
	defer srv.Close()

	_, err := Run(context.Background(), NewClient(defaultOpts()), srv.URL+"/loop", defaultOpts())
	if err == nil {
		t.Fatal("expected a redirect-loop error")
	}
	if !errors.Is(err, ErrRedirectLoop) {
		t.Errorf("want ErrRedirectLoop, got %v", err)
	}
}

func TestRunNoFollow(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/next", http.StatusFound)
	}))
	defer srv.Close()

	opts := defaultOpts()
	opts.NoFollow = true
	res, err := Run(context.Background(), NewClient(opts), srv.URL+"/start", opts)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(res.Chain) != 1 {
		t.Fatalf("--no-follow should yield a single hop, got %d", len(res.Chain))
	}
	if res.Final.StatusCode != http.StatusFound {
		t.Errorf("final status: want 302, got %d", res.Final.StatusCode)
	}
}

func TestRunHEADMethod(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodHead {
			t.Errorf("server saw method %q, want HEAD", r.Method)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	opts := defaultOpts()
	opts.Method = "HEAD"
	res, err := Run(context.Background(), NewClient(opts), srv.URL+"/", opts)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Chain[0].Method != "HEAD" {
		t.Errorf("hop method: want HEAD, got %q", res.Chain[0].Method)
	}
}

func TestClassifyHeaders(t *testing.T) {
	h := http.Header{}
	h.Set("Cache-Control", "max-age=60")
	h.Set("ETag", `"abc"`)
	h.Set("Strict-Transport-Security", "max-age=31536000")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Content-Type", "text/html") // neither caching nor security

	caching, security := ClassifyHeaders(h)

	if len(caching) != 2 {
		t.Fatalf("want 2 caching headers, got %d: %+v", len(caching), caching)
	}
	if caching[0].Name != "Cache-Control" || caching[1].Name != "ETag" {
		t.Errorf("caching order wrong: %+v", caching)
	}
	if len(security) != 2 {
		t.Fatalf("want 2 security headers, got %d: %+v", len(security), security)
	}
	if security[0].Name != "Strict-Transport-Security" || security[1].Name != "X-Frame-Options" {
		t.Errorf("security order wrong: %+v", security)
	}
}

func TestAllHeadersSortedAndJoined(t *testing.T) {
	h := http.Header{}
	h.Set("Zeta", "1")
	h.Set("Alpha", "2")
	h.Add("Vary", "Accept")
	h.Add("Vary", "Origin")

	all := AllHeaders(h)
	if all[0].Name != "Alpha" {
		t.Errorf("headers should be sorted; first is %q", all[0].Name)
	}
	for _, kv := range all {
		if kv.Name == "Vary" && kv.Value != "Accept, Origin" {
			t.Errorf("multi-valued header not joined: %q", kv.Value)
		}
	}
}

func TestSummarizeTLS(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	opts := defaultOpts()
	opts.Insecure = true // httptest uses a self-signed cert
	res, err := Run(context.Background(), NewClient(opts), srv.URL, opts)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.TLS == nil {
		t.Fatal("expected TLS info for an https server")
	}
	if res.TLS.Version == "" {
		t.Error("TLS version not parsed")
	}
	if res.TLS.CipherSuite == "" {
		t.Error("cipher suite not parsed")
	}
	if res.TLS.Cert.NotAfter.IsZero() {
		t.Error("certificate NotAfter not parsed")
	}
}

func TestSummarizeTLSPure(t *testing.T) {
	// Drive SummarizeTLS directly over a synthetic ConnectionState-ish value
	// by connecting to a TLS test server and reading its ConnectionState.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()

	conn, err := tls.Dial("tcp", srv.Listener.Addr().String(), &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // test
	if err != nil {
		t.Fatalf("tls.Dial: %v", err)
	}
	defer conn.Close()
	cs := conn.ConnectionState()

	info := SummarizeTLS(&cs)
	if info.Version == "" || info.CipherSuite == "" {
		t.Errorf("SummarizeTLS returned empty version/cipher: %+v", info)
	}
	if len(cs.PeerCertificates) > 0 && info.Cert.Subject == "" {
		t.Error("expected a certificate subject")
	}
}

func TestExitCode(t *testing.T) {
	cases := []struct {
		name   string
		status int
		err    error
		want   int
	}{
		{"ok 200", 200, nil, 0},
		{"redirect 302", 302, nil, 0},
		{"client 404", 404, nil, 1},
		{"server 500", 500, nil, 1},
		{"error", 0, context.DeadlineExceeded, 2},
	}
	for _, c := range cases {
		if got := ExitCode(c.status, c.err); got != c.want {
			t.Errorf("%s: ExitCode(%d, %v) = %d, want %d", c.name, c.status, c.err, got, c.want)
		}
	}
}

func TestJSONShapeStable(t *testing.T) {
	res := &Result{
		RequestURL: "https://example.com/",
		Chain: []Hop{
			{Method: "GET", URL: "https://example.com/", StatusCode: 200, Status: "200 OK"},
		},
		Final: Final{
			URL:        "https://example.com/",
			StatusCode: 200,
			Status:     "200 OK",
			Proto:      "HTTP/2.0",
			Headers: func() http.Header {
				h := http.Header{}
				h.Set("Cache-Control", "max-age=0")
				h.Set("Content-Security-Policy", "default-src 'self'")
				h.Set("Content-Type", "text/html")
				return h
			}(),
		},
		Timing: Timing{Total: 123 * time.Millisecond, DNSLookup: 1 * time.Millisecond},
	}

	b, err := json.Marshal(res)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, key := range []string{"request_url", "chain", "final", "tls", "timing", "exit_code"} {
		if _, ok := decoded[key]; !ok {
			t.Errorf("JSON missing top-level key %q", key)
		}
	}
	final := decoded["final"].(map[string]any)
	for _, key := range []string{"url", "status_code", "status", "proto", "caching_headers", "security_headers", "headers"} {
		if _, ok := final[key]; !ok {
			t.Errorf("JSON final missing key %q", key)
		}
	}
	timing := decoded["timing"].(map[string]any)
	if timing["total_ms"].(float64) != 123 {
		t.Errorf("total_ms: want 123, got %v", timing["total_ms"])
	}
	if decoded["exit_code"].(float64) != 0 {
		t.Errorf("exit_code: want 0, got %v", decoded["exit_code"])
	}
	// Empty chain/headers must serialize as [] not null for a stable shape.
	empty := (&Result{}).ToJSONResult()
	eb, _ := json.Marshal(empty)
	var em map[string]any
	_ = json.Unmarshal(eb, &em)
	if _, ok := em["chain"].([]any); !ok {
		t.Errorf("empty chain should be [] array, got %T", em["chain"])
	}
}

func TestNormalizeURL(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"example.com", "https://example.com", false},
		{"http://example.com/x", "http://example.com/x", false},
		{"https://example.com", "https://example.com", false},
		{"example.com/path?q=1", "https://example.com/path?q=1", false},
		{"", "", true},
		{"ftp://example.com", "", true},
		{"https://", "", true},
	}
	for _, c := range cases {
		got, err := NormalizeURL(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("NormalizeURL(%q): expected error", c.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("NormalizeURL(%q): unexpected error %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("NormalizeURL(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestParseHeader(t *testing.T) {
	cases := []struct {
		in      string
		name    string
		value   string
		wantErr bool
	}{
		{"Accept: application/json", "Accept", "application/json", false},
		{"X-Empty:", "X-Empty", "", false},
		{"  Key :  spaced value ", "Key", "spaced value", false},
		{"noColon", "", "", true},
		{": novalue", "", "", true},
	}
	for _, c := range cases {
		name, value, err := ParseHeader(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("ParseHeader(%q): expected error", c.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseHeader(%q): unexpected error %v", c.in, err)
			continue
		}
		if name != c.name || value != c.value {
			t.Errorf("ParseHeader(%q) = (%q, %q), want (%q, %q)", c.in, name, value, c.name, c.value)
		}
	}
}

func TestRunSendsHeadersAndUserAgent(t *testing.T) {
	var gotUA, gotAccept string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA = r.Header.Get("User-Agent")
		gotAccept = r.Header.Get("Accept")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	opts := defaultOpts()
	opts.Headers = []string{"Accept: application/json"}
	if _, err := Run(context.Background(), NewClient(opts), srv.URL, opts); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if gotUA != "httppeek-test" {
		t.Errorf("User-Agent: want httppeek-test, got %q", gotUA)
	}
	if gotAccept != "application/json" {
		t.Errorf("Accept: want application/json, got %q", gotAccept)
	}
}
