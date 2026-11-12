package probe

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Cookie is one Set-Cookie header as httppeek reports it. The value itself is
// never kept: only its length, so reports are safe to paste.
type Cookie struct {
	Hop         int      `json:"hop"`         // 1-based index into the chain
	Name        string   `json:"name"`        // may be empty (a nameless cookie)
	ValueBytes  int      `json:"value_bytes"` // length of the value
	Domain      string   `json:"domain,omitempty"`
	Path        string   `json:"path,omitempty"`
	Expires     string   `json:"expires,omitempty"`
	MaxAge      *int64   `json:"max_age,omitempty"`
	Secure      bool     `json:"secure"`
	HttpOnly    bool     `json:"http_only"`
	SameSite    string   `json:"same_site,omitempty"` // as written; empty when absent
	Partitioned bool     `json:"partitioned"`
	Rejected    []string `json:"rejected"` // why a browser would ignore the cookie
	Warnings    []string `json:"warnings"` // risky but accepted

	// Facts about the dropped value that the checks still need.
	hasPath     bool   // a Path attribute was present
	valuePrefix string // "__secure-" or "__host-" when a nameless value starts so
	hasCTL      bool   // the name or value holds a control character
}

// maxCookieAge is the expiry cap RFC 6265bis recommends (Section 5.5) and
// tells user agents to apply when parsing Expires and Max-Age.
const maxCookieAge = 400 * 24 * time.Hour

// ParseSetCookie parses a Set-Cookie value following the parsing algorithm
// of RFC 6265bis Section 5.6: the first ";" ends the name-value pair, a pair
// without "=" is a nameless cookie, attribute names are case-insensitive, and
// the last occurrence of an attribute wins.
func ParseSetCookie(line string) Cookie {
	var c Cookie
	pair, attrs, _ := strings.Cut(line, ";")
	value := pair
	if name, v, ok := strings.Cut(pair, "="); ok {
		c.Name = strings.Trim(name, " \t")
		value = v
	}
	value = strings.Trim(value, " \t")
	c.ValueBytes = len(value)
	c.hasCTL = hasControl(c.Name) || hasControl(value)
	if c.Name == "" {
		lower := strings.ToLower(value)
		for _, prefix := range []string{"__secure-", "__host-"} {
			if strings.HasPrefix(lower, prefix) {
				c.valuePrefix = prefix
			}
		}
	}
	for _, attr := range strings.Split(attrs, ";") {
		name, value, _ := strings.Cut(attr, "=")
		name = strings.ToLower(strings.Trim(name, " \t"))
		value = strings.Trim(value, " \t")
		switch name {
		case "expires":
			c.Expires = value
		case "max-age":
			if n, err := strconv.ParseInt(value, 10, 64); err == nil {
				c.MaxAge = &n
			}
		case "domain":
			c.Domain = strings.ToLower(strings.TrimPrefix(value, "."))
		case "path":
			c.Path = value
			c.hasPath = true
		case "secure":
			c.Secure = true
		case "httponly":
			c.HttpOnly = true
		case "samesite":
			c.SameSite = value
		case "partitioned":
			c.Partitioned = true
		}
	}
	return c
}

// hasControl reports a %x00-08 / %x0A-1F / %x7F character (CTLs but HTAB).
func hasControl(s string) bool {
	for i := 0; i < len(s); i++ {
		if b := s[i]; (b < 0x20 && b != '\t') || b == 0x7F {
			return true
		}
	}
	return false
}

// maxNameValue is the limit on name plus value (RFC 6265bis Section 5.6).
const maxNameValue = 4096

// CheckCookie fills in Rejected and Warnings for a cookie set by a response
// from responseURL, following the parsing and storage model of RFC 6265bis
// (Sections 5.6 and 5.7: the size and control-character checks, the Domain
// check, and steps 13, 19, 20, 21, and 22) plus a few common pitfalls. now is
// used to judge Expires.
func CheckCookie(c *Cookie, responseURL string, now time.Time) {
	c.Rejected = []string{}
	c.Warnings = []string{}
	u, err := url.Parse(responseURL)
	if err != nil {
		return
	}
	secureOrigin := u.Scheme == "https"
	host := strings.ToLower(u.Hostname())
	lowerName := strings.ToLower(c.Name)
	sameSite := strings.ToLower(c.SameSite)

	if len(c.Name)+c.ValueBytes > maxNameValue {
		c.Rejected = append(c.Rejected, fmt.Sprintf("name and value are %d bytes, over the %d-byte limit", len(c.Name)+c.ValueBytes, maxNameValue))
	}
	if c.hasCTL {
		c.Rejected = append(c.Rejected, "control character in the name or value")
	}
	if c.Secure && !secureOrigin {
		c.Rejected = append(c.Rejected, "Secure cookie set over plain http")
	}
	if c.Domain != "" && !domainMatch(host, c.Domain) {
		c.Rejected = append(c.Rejected, "Domain="+c.Domain+" does not cover the host "+host)
	}
	if sameSite == "none" && !c.Secure {
		c.Rejected = append(c.Rejected, "SameSite=None without Secure")
	}
	if strings.HasPrefix(lowerName, "__secure-") && !c.Secure {
		c.Rejected = append(c.Rejected, "__Secure- prefix without Secure")
	}
	if strings.HasPrefix(lowerName, "__host-") {
		if !c.Secure {
			c.Rejected = append(c.Rejected, "__Host- prefix without Secure")
		}
		if c.Domain != "" {
			c.Rejected = append(c.Rejected, "__Host- prefix with a Domain attribute")
		}
		if !c.hasPath || cookiePath(c.Path, u) != "/" {
			c.Rejected = append(c.Rejected, "__Host- prefix without Path=/")
		}
	}
	switch c.valuePrefix {
	case "__secure-":
		c.Rejected = append(c.Rejected, "nameless cookie whose value starts with __Secure-")
	case "__host-":
		c.Rejected = append(c.Rejected, "nameless cookie whose value starts with __Host-")
	}

	if secureOrigin && !c.Secure {
		c.Warnings = append(c.Warnings, "no Secure: also sent over plain http")
	}
	if !c.HttpOnly {
		c.Warnings = append(c.Warnings, "no HttpOnly: readable by page scripts")
	}
	switch sameSite {
	case "":
		c.Warnings = append(c.Warnings, "no SameSite: the browser's default applies")
	case "strict", "lax", "none":
	default:
		c.Warnings = append(c.Warnings, "SameSite="+c.SameSite+" is not Strict, Lax, or None and is ignored")
	}
	if longerThanCap(c, now) {
		c.Warnings = append(c.Warnings, "lifetime over 400 days: browsers cut it to 400")
	}
}

// longerThanCap reports whether Max-Age (which wins) or Expires asks for a
// lifetime over the 400-day cap. Max-Age is compared in seconds, so huge
// values cannot overflow a Duration.
func longerThanCap(c *Cookie, now time.Time) bool {
	if c.MaxAge != nil {
		return *c.MaxAge > int64(maxCookieAge/time.Second)
	}
	if c.Expires == "" {
		return false
	}
	for _, layout := range []string{time.RFC1123, "Mon, 02-Jan-2006 15:04:05 MST", time.RFC850, time.ANSIC} {
		if t, err := time.Parse(layout, c.Expires); err == nil {
			return t.Sub(now) > maxCookieAge
		}
	}
	return false
}

// cookiePath is the path a Path attribute gives (RFC 6265bis Section
// 5.6.4): the value when it starts with "/", else the default-path of the
// request URI (Section 5.1.4).
func cookiePath(attr string, u *url.URL) string {
	if strings.HasPrefix(attr, "/") {
		return attr
	}
	p := u.EscapedPath()
	if !strings.HasPrefix(p, "/") || strings.Count(p, "/") == 1 {
		return "/"
	}
	return p[:strings.LastIndex(p, "/")]
}

// domainMatch reports whether host domain-matches domain (RFC 6265bis
// Section 5.1.3): equal, or host ends with "."+domain and is not an IP.
func domainMatch(host, domain string) bool {
	if host == domain {
		return true
	}
	if net.ParseIP(host) != nil {
		return false
	}
	return strings.HasSuffix(host, "."+domain)
}

// CollectCookies parses and checks every Set-Cookie header in the chain.
func CollectCookies(chain []Hop, now time.Time) []Cookie {
	out := []Cookie{}
	for i, hop := range chain {
		for _, line := range hop.SetCookie {
			c := ParseSetCookie(line)
			c.Hop = i + 1
			CheckCookie(&c, hop.URL, now)
			out = append(out, c)
		}
	}
	return out
}
