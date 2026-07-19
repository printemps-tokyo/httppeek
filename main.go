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
	"os"
	"strings"
	"time"

	"github.com/printemps-tokyo/httppeek/internal/probe"
)

// version is overridden at build time via -ldflags "-X main.version=...".
var version = "dev"

const usage = `httppeek - HTTP diagnostics: redirects, headers, TLS, and timing

Usage:
  httppeek [flags] <url>

The URL may omit its scheme; https:// is assumed when none is given.

Flags:
  --method <m>        Request method: GET (default) or HEAD
  --header "K: V"     Add a request header (repeatable)
  --timeout <dur>     Per-request timeout (default 10s), e.g. 5s, 1500ms
  --max-redirects <n> Maximum redirect hops to follow (default 10)
  --no-follow         Show only the first response, do not follow redirects
  --insecure          Skip TLS certificate verification (prints a warning)
  --user-agent <ua>   Set the User-Agent header (default httppeek/<version>)
  --json              Emit structured JSON (chain + headers + tls + timing)
  --version           Print version and exit
  --help              Show this help and exit

Exit codes:
  0  successful fetch with a final 2xx or 3xx status
  1  the final response status is >= 400
  2  the request errored, or arguments were invalid

Examples:
  httppeek example.com
  httppeek --method HEAD https://example.com
  httppeek --header "Accept: application/json" --json api.example.com
`

// config is the parsed command line.
type config struct {
	url         string
	opts        probe.Options
	jsonOut     bool
	showVersion bool
	showHelp    bool
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
	if cfg.url == "" {
		fmt.Fprintf(stderr, "httppeek: missing <url>\n\nRun 'httppeek --help' for usage.\n")
		return 2
	}

	normalized, err := probe.NormalizeURL(cfg.url)
	if err != nil {
		fmt.Fprintf(stderr, "httppeek: %v\n", err)
		return 2
	}

	if cfg.opts.Insecure {
		fmt.Fprintln(stderr, "httppeek: warning: --insecure disables TLS certificate verification")
	}

	client := probe.NewClient(cfg.opts)
	ctx, cancel := context.WithTimeout(context.Background(), cfg.opts.Timeout+5*time.Second)
	defer cancel()

	result, err := probe.Run(ctx, client, normalized, cfg.opts)
	if err != nil {
		fmt.Fprintf(stderr, "httppeek: %v\n", err)
		return probe.ExitCode(0, err)
	}

	if cfg.jsonOut {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if encErr := enc.Encode(result.ToJSONResult()); encErr != nil {
			fmt.Fprintf(stderr, "httppeek: %v\n", encErr)
			return 2
		}
	} else {
		writeText(stdout, result)
	}

	return probe.ExitCode(result.Final.StatusCode, nil)
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
			if cfg.url != "" {
				return cfg, fmt.Errorf("unexpected extra argument %q", arg)
			}
			cfg.url = arg
		}
	}
	return cfg, nil
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

	if r.TLS != nil {
		writeTLS(w, r.TLS)
	}

	writeTiming(w, r.Timing)
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
