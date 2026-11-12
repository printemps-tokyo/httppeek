package probe

import (
	"encoding/json"
	"time"
)

// JSONTiming is the JSON representation of Timing, with durations expressed in
// milliseconds for stability and readability.
type JSONTiming struct {
	DNSLookupMS       float64 `json:"dns_lookup_ms"`
	TCPConnectMS      float64 `json:"tcp_connect_ms"`
	TLSHandshakeMS    float64 `json:"tls_handshake_ms"`
	TimeToFirstByteMS float64 `json:"time_to_first_byte_ms"`
	TotalMS           float64 `json:"total_ms"`
}

// JSONFinal is the JSON representation of the final response.
type JSONFinal struct {
	URL             string     `json:"url"`
	StatusCode      int        `json:"status_code"`
	Status          string     `json:"status"`
	Proto           string     `json:"proto"`
	CachingHeaders  []HeaderKV `json:"caching_headers"`
	SecurityHeaders []HeaderKV `json:"security_headers"`
	Headers         []HeaderKV `json:"headers"`
}

// JSONResult is the stable, machine-readable shape emitted by --json.
type JSONResult struct {
	RequestURL string     `json:"request_url"`
	Chain      []Hop      `json:"chain"`
	Final      JSONFinal  `json:"final"`
	TLS        *TLSInfo   `json:"tls"`
	Timing     JSONTiming `json:"timing"`
	Cookies    []Cookie   `json:"cookies"`
	HTTP3      *HTTP3Info `json:"http3"`
	ExitCode   int        `json:"exit_code"`
}

// JSONError is the JSON entry for a URL whose request failed, used in the
// array that several URLs produce.
type JSONError struct {
	RequestURL string `json:"request_url"`
	Error      string `json:"error"`
	ExitCode   int    `json:"exit_code"`
}

// ToJSONResult converts a Result into its stable JSON representation.
func (r *Result) ToJSONResult() JSONResult {
	caching, security := ClassifyHeaders(r.Final.Headers)
	out := JSONResult{
		RequestURL: r.RequestURL,
		Chain:      r.Chain,
		Final: JSONFinal{
			URL:             r.Final.URL,
			StatusCode:      r.Final.StatusCode,
			Status:          r.Final.Status,
			Proto:           r.Final.Proto,
			CachingHeaders:  caching,
			SecurityHeaders: security,
			Headers:         AllHeaders(r.Final.Headers),
		},
		TLS:      r.TLS,
		Timing:   toJSONTiming(r.Timing),
		Cookies:  r.Cookies,
		HTTP3:    r.HTTP3,
		ExitCode: ExitCode(r.Final.StatusCode, nil),
	}
	if out.Cookies == nil {
		out.Cookies = []Cookie{}
	}
	if out.Chain == nil {
		out.Chain = []Hop{}
	}
	if out.Final.CachingHeaders == nil {
		out.Final.CachingHeaders = []HeaderKV{}
	}
	if out.Final.SecurityHeaders == nil {
		out.Final.SecurityHeaders = []HeaderKV{}
	}
	if out.Final.Headers == nil {
		out.Final.Headers = []HeaderKV{}
	}
	return out
}

func toJSONTiming(t Timing) JSONTiming {
	ms := func(d time.Duration) float64 { return float64(d) / float64(time.Millisecond) }
	return JSONTiming{
		DNSLookupMS:       ms(t.DNSLookup),
		TCPConnectMS:      ms(t.TCPConnect),
		TLSHandshakeMS:    ms(t.TLSHandshake),
		TimeToFirstByteMS: ms(t.TimeToFirstByte),
		TotalMS:           ms(t.Total),
	}
}

// MarshalJSON renders the result as indented JSON.
func (r *Result) MarshalJSON() ([]byte, error) {
	return json.Marshal(r.ToJSONResult())
}
