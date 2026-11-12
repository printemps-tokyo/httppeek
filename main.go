// Command httppeek is a single-command HTTP diagnostic CLI: given a URL it
// follows and prints the redirect chain, the final status and response
// headers (highlighting caching and security headers), TLS details for https,
// and per-phase timing. It is a read-only diagnostic client and sends data
// only to the URL you name.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	"github.com/printemps-tokyo/httppeek/internal/probe"
)

// version is overridden at build time via -ldflags "-X main.version=...".
var version = "dev"

const usage = `httppeek - HTTP diagnostics: redirects, headers, cookies, TLS, HTTP/3, and timing

Usage:
  httppeek [flags] <url> [<url>...]

The URL may omit its scheme; https:// is assumed when none is given. With
several URLs, httppeek fetches them in parallel and prints a comparison.

Flags:
  --method <m>        Request method: GET (default) or HEAD
  --header "K: V"     Add a request header (repeatable)
  --timeout <dur>     Per-request timeout (default 10s), e.g. 5s, 1500ms
  --max-redirects <n> Maximum redirect hops to follow (default 10)
  --no-follow         Show only the first response, do not follow redirects
  --insecure          Skip TLS certificate verification (prints a warning)
  --user-agent <ua>   Set the User-Agent header (default httppeek/<version>)
  --dns <server>      DNS server for the HTTPS record lookup (default: the
                      first nameserver in /etc/resolv.conf)
  --no-dns            Skip the HTTPS record lookup (HTTP/3 then comes from
                      Alt-Svc only)
  --full              With several URLs, also print each full report
  --json              Emit structured JSON (one object, or an array for
                      several URLs)
  --version           Print version and exit
  --help              Show this help and exit

Exit codes (with several URLs, the highest one):
  0  successful fetch with a final 2xx or 3xx status
  1  the final response status is >= 400
  2  the request errored, or arguments were invalid

Examples:
  httppeek example.com
  httppeek --method HEAD https://example.com
  httppeek --header "Accept: application/json" --json api.example.com
  httppeek example.com www.example.com example.net
`

// config is the parsed command line.
type config struct {
	urls        []string
	opts        probe.Options
	jsonOut     bool
	full        bool
	dnsServer   string
	noDNS       bool
	showVersion bool
	showHelp    bool
}

// maxParallel bounds how many URLs are fetched at once.
const maxParallel = 4

// outcome is one URL's probe result or error.
type outcome struct {
	url    string
	result *probe.Result
	err    error
}

func (o outcome) exitCode() int {
	if o.err != nil {
		return probe.ExitCode(0, o.err)
	}
	return probe.ExitCode(o.result.Final.StatusCode, nil)
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run parses args, performs the probe, writes output, and returns the exit
// code. It is kept separate from main so it can be exercised in tests.
func run(args []string, stdout, stderr io.Writer) int {
	cfg, err := parseArgs(args)
	if err != nil {
		fmt.Fprintf(stderr, "httppeek: %v\n\nRun 'httppeek --help' for usage.\n", err)
		return 2
	}
	if cfg.showHelp {
		fmt.Fprint(stdout, usage)
		return 0
	}
	if cfg.showVersion {
		fmt.Fprintf(stdout, "httppeek %s\n", version)
		return 0
	}
	if len(cfg.urls) == 0 {
		fmt.Fprintf(stderr, "httppeek: missing <url>\n\nRun 'httppeek --help' for usage.\n")
		return 2
	}

	normalized := make([]string, len(cfg.urls))
	for i, raw := range cfg.urls {
		n, err := probe.NormalizeURL(raw)
		if err != nil {
			fmt.Fprintf(stderr, "httppeek: %v\n", err)
			return 2
		}
		normalized[i] = n
	}

	if cfg.opts.Insecure {
		fmt.Fprintln(stderr, "httppeek: warning: --insecure disables TLS certificate verification")
	}

	dnsServer := ""
	if !cfg.noDNS {
		dnsServer = cfg.dnsServer
		if dnsServer == "" {
			dnsServer = probe.SystemNameserver()
		}
	}

	outcomes := probeAll(normalized, cfg.opts, dnsServer)

	code := 0
	for _, o := range outcomes {
		if c := o.exitCode(); c > code {
			code = c
		}
	}

	if cfg.jsonOut {
		var payload any
		if len(outcomes) == 1 {
			o := outcomes[0]
			if o.err != nil {
				fmt.Fprintf(stderr, "httppeek: %v\n", o.err)
				return code
			}
			payload = o.result.ToJSONResult()
		} else {
			items := make([]any, len(outcomes))
			for i, o := range outcomes {
				if o.err != nil {
					items[i] = probe.JSONError{RequestURL: o.url, Error: o.err.Error(), ExitCode: o.exitCode()}
				} else {
					items[i] = o.result.ToJSONResult()
				}
			}
			payload = items
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if encErr := enc.Encode(payload); encErr != nil {
			fmt.Fprintf(stderr, "httppeek: %v\n", encErr)
			return 2
		}
		return code
	}

	if len(outcomes) == 1 {
		o := outcomes[0]
		if o.err != nil {
			fmt.Fprintf(stderr, "httppeek: %v\n", o.err)
			return code
		}
		writeText(stdout, o.result)
		return code
	}

	writeComparison(stdout, outcomes)
	for _, o := range outcomes {
		if o.err != nil {
			fmt.Fprintf(stderr, "httppeek: %s: %v\n", o.url, o.err)
		}
	}
	if cfg.full {
		for _, o := range outcomes {
			if o.err == nil {
				fmt.Fprintf(stdout, "\n%s\n\n", strings.Repeat("=", 72))
				writeText(stdout, o.result)
			}
		}
	}
	return code
}

// probeAll fetches every URL (up to maxParallel at once) and returns the
// outcomes in input order. Each URL gets its own client and deadline.
func probeAll(urls []string, opts probe.Options, dnsServer string) []outcome {
	outcomes := make([]outcome, len(urls))
	sem := make(chan struct{}, maxParallel)
	var wg sync.WaitGroup
	for i, u := range urls {
		wg.Add(1)
		go func(i int, u string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			outcomes[i] = probeOne(u, opts, dnsServer)
		}(i, u)
	}
	wg.Wait()
	return outcomes
}

func probeOne(rawURL string, opts probe.Options, dnsServer string) outcome {
	client := probe.NewClient(opts)
	ctx, cancel := context.WithTimeout(context.Background(), 2*opts.Timeout+5*time.Second)
	defer cancel()

	result, err := probe.Run(ctx, client, rawURL, opts)
	if err != nil {
		return outcome{url: rawURL, err: err}
	}
	result.Cookies = probe.CollectCookies(result.Chain, time.Now())
	h3 := probe.CheckHTTP3(ctx, result.Final.Headers.Values("Alt-Svc"), result.Final.URL, dnsServer, opts.Timeout)
	result.HTTP3 = &h3
	return outcome{url: rawURL, result: result}
}

// parseArgs is a small hand-rolled parser (stdlib flag would also work, but a
// hand-rolled one keeps repeatable --header simple and the help text ours).
func parseArgs(args []string) (config, error) {
	cfg := config{
		opts: probe.Options{
			Method:       "GET",
			Timeout:      10 * time.Second,
			MaxRedirects: 10,
			UserAgent:    "httppeek/" + version,
		},
	}

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--help" || arg == "-h":
			cfg.showHelp = true
		case arg == "--version" || arg == "-V":
			cfg.showVersion = true
		case arg == "--json":
			cfg.jsonOut = true
		case arg == "--no-follow":
			cfg.opts.NoFollow = true
		case arg == "--insecure":
			cfg.opts.Insecure = true
		case arg == "--full":
			cfg.full = true
		case arg == "--no-dns":
			cfg.noDNS = true
		case arg == "--dns" || strings.HasPrefix(arg, "--dns="):
			v, err := valueFor(arg, &i, args, "--dns")
			if err != nil {
				return cfg, err
			}
			server, perr := dnsAddress(v)
			if perr != nil {
				return cfg, perr
			}
			cfg.dnsServer = server
		case arg == "--method" || strings.HasPrefix(arg, "--method="):
			v, err := valueFor(arg, &i, args, "--method")
			if err != nil {
				return cfg, err
			}
			m := strings.ToUpper(v)
			if m != "GET" && m != "HEAD" {
				return cfg, fmt.Errorf("unsupported --method %q: use GET or HEAD", v)
			}
			cfg.opts.Method = m
		case arg == "--header" || strings.HasPrefix(arg, "--header="):
			v, err := valueFor(arg, &i, args, "--header")
			if err != nil {
				return cfg, err
			}
			if _, _, perr := probe.ParseHeader(v); perr != nil {
				return cfg, perr
			}
			cfg.opts.Headers = append(cfg.opts.Headers, v)
		case arg == "--timeout" || strings.HasPrefix(arg, "--timeout="):
			v, err := valueFor(arg, &i, args, "--timeout")
			if err != nil {
				return cfg, err
			}
			d, perr := time.ParseDuration(v)
			if perr != nil {
				return cfg, fmt.Errorf("invalid --timeout %q: %w", v, perr)
			}
			if d <= 0 {
				return cfg, fmt.Errorf("invalid --timeout %q: must be positive", v)
			}
			cfg.opts.Timeout = d
		case arg == "--max-redirects" || strings.HasPrefix(arg, "--max-redirects="):
			v, err := valueFor(arg, &i, args, "--max-redirects")
			if err != nil {
				return cfg, err
			}
			n, perr := parseNonNegInt(v)
			if perr != nil {
				return cfg, fmt.Errorf("invalid --max-redirects %q: %w", v, perr)
			}
			cfg.opts.MaxRedirects = n
		case arg == "--user-agent" || strings.HasPrefix(arg, "--user-agent="):
			v, err := valueFor(arg, &i, args, "--user-agent")
			if err != nil {
				return cfg, err
			}
			cfg.opts.UserAgent = v
		case strings.HasPrefix(arg, "-") && arg != "-":
			return cfg, fmt.Errorf("unknown flag %q", arg)
		default:
			cfg.urls = append(cfg.urls, arg)
		}
	}
	if cfg.noDNS && cfg.dnsServer != "" {
		return cfg, errors.New("--dns and --no-dns cannot be combined")
	}
	return cfg, nil
}

// dnsAddress turns "1.1.1.1", "[2606:4700::1111]:53", or "host:5353" into a
// dialable "host:port", defaulting the port to 53.
func dnsAddress(v string) (string, error) {
	if v == "" {
		return "", errors.New("--dns needs a server address")
	}
	if host, port, err := net.SplitHostPort(v); err == nil {
		if host == "" || port == "" {
			return "", fmt.Errorf("invalid --dns %q", v)
		}
		return v, nil
	}
	if strings.Count(v, ":") > 1 || !strings.Contains(v, ":") {
		return net.JoinHostPort(strings.Trim(v, "[]"), "53"), nil
	}
	return "", fmt.Errorf("invalid --dns %q", v)
}

// valueFor returns the value for a flag given either "--flag=value" or the
// following argument.
func valueFor(arg string, i *int, args []string, name string) (string, error) {
	if eq := strings.IndexByte(arg, '='); eq >= 0 {
		return arg[eq+1:], nil
	}
	if *i+1 >= len(args) {
		return "", fmt.Errorf("flag %s needs a value", name)
	}
	*i++
	return args[*i], nil
}

func parseNonNegInt(s string) (int, error) {
	if s == "" {
		return 0, errors.New("empty value")
	}
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, fmt.Errorf("not a non-negative integer: %q", s)
		}
		n = n*10 + int(r-'0')
	}
	return n, nil
}

// writeText renders a human-readable report.
func writeText(w io.Writer, r *probe.Result) {
	fmt.Fprintf(w, "URL: %s\n\n", r.RequestURL)

	if len(r.Chain) > 1 {
		fmt.Fprintln(w, "Redirect chain")
		for i, hop := range r.Chain {
			fmt.Fprintf(w, "  %d. %s %s\n", i+1, hop.Method, hop.URL)
			fmt.Fprintf(w, "     %d %s\n", hop.StatusCode, statusText(hop.Status, hop.StatusCode))
			if hop.Location != "" {
				fmt.Fprintf(w, "     -> Location: %s\n", hop.Location)
			}
		}
		fmt.Fprintln(w)
	}

	fmt.Fprintln(w, "Final response")
	fmt.Fprintf(w, "  %s\n", r.Final.URL)
	fmt.Fprintf(w, "  %s %d %s\n", r.Final.Proto, r.Final.StatusCode, statusText(r.Final.Status, r.Final.StatusCode))
	fmt.Fprintln(w)

	caching, security := probe.ClassifyHeaders(r.Final.Headers)
	writeHeaderGroup(w, "Caching headers", caching)
	writeHeaderGroup(w, "Security headers", security)

	fmt.Fprintln(w, "All response headers")
	for _, h := range probe.AllHeaders(r.Final.Headers) {
		fmt.Fprintf(w, "  %s: %s\n", h.Name, h.Value)
	}
	fmt.Fprintln(w)

	writeCookies(w, r.Cookies)

	if r.TLS != nil {
		writeTLS(w, r.TLS)
	}

	if r.HTTP3 != nil {
		writeHTTP3(w, r.HTTP3)
	}

	writeTiming(w, r.Timing)
}

func writeCookies(w io.Writer, cookies []probe.Cookie) {
	fmt.Fprintln(w, "Cookies")
	if len(cookies) == 0 {
		fmt.Fprintln(w, "  (none set)")
		fmt.Fprintln(w)
		return
	}
	for _, c := range cookies {
		name := c.Name
		if name == "" {
			name = "(nameless)"
		}
		fmt.Fprintf(w, "  %s  (hop %d, value %d bytes)\n", name, c.Hop, c.ValueBytes)
		fmt.Fprintf(w, "    %s\n", cookieAttrs(c))
		for _, r := range c.Rejected {
			fmt.Fprintf(w, "    rejected: %s\n", r)
		}
		for _, warn := range c.Warnings {
			fmt.Fprintf(w, "    warning:  %s\n", warn)
		}
	}
	fmt.Fprintln(w)
}

func cookieAttrs(c probe.Cookie) string {
	var parts []string
	if c.Domain != "" {
		parts = append(parts, "Domain="+c.Domain)
	}
	if c.Path != "" {
		parts = append(parts, "Path="+c.Path)
	}
	switch {
	case c.MaxAge != nil:
		parts = append(parts, fmt.Sprintf("Max-Age=%d", *c.MaxAge))
	case c.Expires != "":
		parts = append(parts, "Expires="+c.Expires)
	default:
		parts = append(parts, "session")
	}
	if c.Secure {
		parts = append(parts, "Secure")
	}
	if c.HttpOnly {
		parts = append(parts, "HttpOnly")
	}
	if c.SameSite != "" {
		parts = append(parts, "SameSite="+c.SameSite)
	}
	if c.Partitioned {
		parts = append(parts, "Partitioned")
	}
	return strings.Join(parts, "; ")
}

func writeHTTP3(w io.Writer, h *probe.HTTP3Info) {
	fmt.Fprintln(w, "HTTP/3 (advertised; httppeek does not connect over QUIC)")
	if h.Advertised {
		fmt.Fprintln(w, "  Advertised:  yes")
	} else {
		fmt.Fprintln(w, "  Advertised:  no")
	}
	switch {
	case h.AltSvcClear:
		fmt.Fprintln(w, "  Alt-Svc:     clear")
	case len(h.AltSvc) == 0:
		fmt.Fprintln(w, "  Alt-Svc:     (none)")
	default:
		for i, a := range h.AltSvc {
			label := "  Alt-Svc:    "
			if i > 0 {
				label = "             "
			}
			line := fmt.Sprintf("%s %s=%q", label, a.Protocol, a.Authority)
			if a.MaxAge > 0 {
				line += fmt.Sprintf(" ma=%d", a.MaxAge)
			}
			fmt.Fprintln(w, line)
		}
	}
	if len(h.Aliases) > 0 {
		fmt.Fprintf(w, "  HTTPS alias: %s -> %s\n", h.QueryName, strings.Join(h.Aliases, " -> "))
	}
	switch {
	case h.DNSServer == "":
		fmt.Fprintln(w, "  HTTPS RR:    (not looked up)")
	case h.DNSError != "":
		fmt.Fprintf(w, "  HTTPS RR:    lookup failed via %s: %s\n", h.DNSServer, h.DNSError)
	case len(h.HTTPSRecords) == 0:
		fmt.Fprintf(w, "  HTTPS RR:    (none, via %s)\n", h.DNSServer)
	default:
		for i, r := range h.HTTPSRecords {
			label := "  HTTPS RR:   "
			if i > 0 {
				label = "             "
			}
			line := fmt.Sprintf("%s %d %s", label, r.Priority, r.Target)
			if len(r.ALPN) > 0 {
				line += " alpn=" + strings.Join(r.ALPN, ",")
			}
			if r.NoDefaultALPN {
				line += " no-default-alpn"
			}
			if r.Port != 0 {
				line += fmt.Sprintf(" port=%d", r.Port)
			}
			fmt.Fprintln(w, line)
		}
	}
	fmt.Fprintln(w)
}

// comparedHeaders are the headers whose differences the comparison lists.
var comparedHeaders = append(append([]string{"Content-Type", "Server"}, probe.CachingHeaderNames...), probe.SecurityHeaderNames...)

// writeComparison prints one row per URL and the headers that differ.
func writeComparison(w io.Writer, outcomes []outcome) {
	fmt.Fprintln(w, "Comparison")
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "  #\tURL\tStatus\tHops\tProto\tTLS\tCert\tHTTP/3\tCookies\tTotal")
	for i, o := range outcomes {
		if o.err != nil {
			fmt.Fprintf(tw, "  %d\t%s\terror\t-\t-\t-\t-\t-\t-\t-\n", i+1, o.url)
			continue
		}
		r := o.result
		tlsVersion, cert := "-", "-"
		if r.TLS != nil {
			tlsVersion = r.TLS.Version
			cert = fmt.Sprintf("%dd", r.TLS.Cert.DaysRemaining)
		}
		h3 := "-"
		if r.HTTP3 != nil {
			h3 = "no"
			if r.HTTP3.Advertised {
				h3 = "yes"
			}
		}
		rejected := 0
		for _, c := range r.Cookies {
			if len(c.Rejected) > 0 {
				rejected++
			}
		}
		cookies := fmt.Sprintf("%d", len(r.Cookies))
		if rejected > 0 {
			cookies += fmt.Sprintf(" (%d rejected)", rejected)
		}
		fmt.Fprintf(tw, "  %d\t%s\t%d\t%d\t%s\t%s\t%s\t%s\t%s\t%s\n",
			i+1, o.url, r.Final.StatusCode, len(r.Chain)-1, r.Final.Proto,
			tlsVersion, cert, h3, cookies, fmtDur(r.Timing.Total))
	}
	tw.Flush()
	fmt.Fprintln(w)

	fmt.Fprintln(w, "Final URLs")
	for i, o := range outcomes {
		if o.err != nil {
			fmt.Fprintf(w, "  %d  error: %v\n", i+1, o.err)
		} else {
			fmt.Fprintf(w, "  %d  %s\n", i+1, o.result.Final.URL)
		}
	}
	fmt.Fprintln(w)

	fmt.Fprintln(w, "Header differences")
	any := false
	for _, name := range comparedHeaders {
		values := make([]string, len(outcomes))
		differ := false
		first := ""
		seenFirst := false
		for i, o := range outcomes {
			if o.err != nil {
				continue
			}
			v := strings.Join(o.result.Final.Headers.Values(name), ", ")
			values[i] = v
			if !seenFirst {
				first, seenFirst = v, true
			} else if v != first {
				differ = true
			}
		}
		if !differ {
			continue
		}
		any = true
		fmt.Fprintf(w, "  %s\n", name)
		for i, o := range outcomes {
			if o.err != nil {
				continue
			}
			fmt.Fprintf(w, "    %d  %s\n", i+1, shorten(values[i]))
		}
	}
	if !any {
		fmt.Fprintln(w, "  (none: the compared headers match)")
	}
}

// maxCompareValue is how much of a header value the comparison prints;
// --full shows the rest.
const maxCompareValue = 120

func shorten(v string) string {
	if v == "" {
		return "(absent)"
	}
	runes := []rune(v)
	if len(runes) <= maxCompareValue {
		return v
	}
	return fmt.Sprintf("%s... (%d chars)", string(runes[:maxCompareValue-3]), len(runes))
}

func writeHeaderGroup(w io.Writer, title string, headers []probe.HeaderKV) {
	fmt.Fprintf(w, "%s\n", title)
	if len(headers) == 0 {
		fmt.Fprintln(w, "  (none present)")
	} else {
		for _, h := range headers {
			fmt.Fprintf(w, "  %s: %s\n", h.Name, h.Value)
		}
	}
	fmt.Fprintln(w)
}

func writeTLS(w io.Writer, t *probe.TLSInfo) {
	fmt.Fprintln(w, "TLS")
	fmt.Fprintf(w, "  Version:      %s\n", t.Version)
	fmt.Fprintf(w, "  Cipher suite: %s\n", t.CipherSuite)
	fmt.Fprintf(w, "  Subject:      %s\n", t.Cert.Subject)
	fmt.Fprintf(w, "  Issuer:       %s\n", t.Cert.Issuer)
	fmt.Fprintf(w, "  Valid:        %s -> %s (%d days remaining)\n",
		t.Cert.NotBefore.Format("2006-01-02"),
		t.Cert.NotAfter.Format("2006-01-02"),
		t.Cert.DaysRemaining)
	if len(t.Cert.DNSNames) > 0 {
		fmt.Fprintf(w, "  SANs:         %s\n", strings.Join(t.Cert.DNSNames, ", "))
	}
	fmt.Fprintln(w)
}

func writeTiming(w io.Writer, t probe.Timing) {
	fmt.Fprintln(w, "Timing (final request)")
	fmt.Fprintf(w, "  DNS lookup:          %s\n", fmtDur(t.DNSLookup))
	fmt.Fprintf(w, "  TCP connect:         %s\n", fmtDur(t.TCPConnect))
	fmt.Fprintf(w, "  TLS handshake:       %s\n", fmtDur(t.TLSHandshake))
	fmt.Fprintf(w, "  Time to first byte:  %s\n", fmtDur(t.TimeToFirstByte))
	fmt.Fprintf(w, "  Total:               %s\n", fmtDur(t.Total))
}

func fmtDur(d time.Duration) string {
	if d <= 0 {
		return "-"
	}
	return d.Round(time.Millisecond).String()
}

// statusText returns the status text, falling back to the standard reason
// phrase when the response carried only a bare code.
func statusText(status string, code int) string {
	trimmed := strings.TrimSpace(strings.TrimPrefix(status, fmt.Sprintf("%d", code)))
	if trimmed != "" {
		return trimmed
	}
	return status
}
