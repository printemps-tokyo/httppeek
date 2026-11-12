package probe

import (
	"context"
	"encoding/binary"
	"net"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestParseSetCookie(t *testing.T) {
	c := ParseSetCookie(`sid=abc123; Path=/app; Domain=.Example.COM; Max-Age=3600; secure; HTTPONLY; SameSite=Lax; Partitioned; Path=/`)
	if c.Name != "sid" || c.ValueBytes != 6 {
		t.Errorf("name/value: %+v", c)
	}
	if c.Domain != "example.com" || c.Path != "/" {
		t.Errorf("last Path wins and Domain drops the dot: %+v", c)
	}
	if c.MaxAge == nil || *c.MaxAge != 3600 || !c.Secure || !c.HttpOnly || c.SameSite != "Lax" || !c.Partitioned {
		t.Errorf("attributes: %+v", c)
	}
	nameless := ParseSetCookie("justavalue; Secure")
	if nameless.Name != "" || nameless.ValueBytes != 10 || !nameless.Secure {
		t.Errorf("nameless: %+v", nameless)
	}
}

func TestCheckCookieFollowsRFC6265bis(t *testing.T) {
	now := time.Date(2026, 11, 12, 0, 0, 0, 0, time.UTC)
	check := func(line, from string) Cookie {
		c := ParseSetCookie(line)
		CheckCookie(&c, from, now)
		return c
	}
	cases := []struct {
		line, from string
		rejected   []string
	}{
		{"a=1; Secure", "http://example.com/", []string{"Secure cookie set over plain http"}},
		{"a=1; SameSite=None", "https://example.com/", []string{"SameSite=None without Secure"}},
		{"__Secure-a=1", "https://example.com/", []string{"__Secure- prefix without Secure"}},
		{"__SECURE-a=1", "https://example.com/", []string{"__Secure- prefix without Secure"}},
		{"__Host-a=1; Secure; Domain=example.com; Path=/", "https://example.com/", []string{"__Host- prefix with a Domain attribute"}},
		{"__Host-a=1; Secure", "https://example.com/", []string{"__Host- prefix without Path=/"}},
		{"a=1; Domain=other.example", "https://example.com/", []string{"Domain=other.example does not cover the host example.com"}},
		{"a=1; Domain=example.com", "https://www.example.com/", []string{}},
		{"a=1; Domain=ample.com", "https://example.com/", []string{"Domain=ample.com does not cover the host example.com"}},
		{"__Host-a=1; Secure; Path=/; HttpOnly; SameSite=Strict", "https://example.com/", []string{}},
	}
	for _, tc := range cases {
		c := check(tc.line, tc.from)
		if !reflect.DeepEqual(c.Rejected, tc.rejected) {
			t.Errorf("%q from %s: rejected %q, want %q", tc.line, tc.from, c.Rejected, tc.rejected)
		}
	}

	good := check("__Host-a=1; Secure; Path=/; HttpOnly; SameSite=Strict", "https://example.com/")
	if len(good.Warnings) != 0 {
		t.Errorf("good cookie warnings: %q", good.Warnings)
	}
	loose := check("a=1; Max-Age=40000000; SameSite=Loose", "https://example.com/")
	for _, want := range []string{"no Secure", "no HttpOnly", "SameSite=Loose", "over 400 days"} {
		if !strings.Contains(strings.Join(loose.Warnings, "|"), want) {
			t.Errorf("missing warning %q in %q", want, loose.Warnings)
		}
	}
	expires := check("a=1; Expires=Wed, 01 Jan 2031 00:00:00 GMT; Secure; HttpOnly; SameSite=Lax", "https://example.com/")
	if !strings.Contains(strings.Join(expires.Warnings, "|"), "over 400 days") {
		t.Errorf("Expires beyond 400 days: %q", expires.Warnings)
	}
}

func TestRedactSetCookie(t *testing.T) {
	for in, want := range map[string]string{
		"sid=abc; Path=/":  "sid=<3 bytes>; Path=/",
		"sid=":             "sid=<0 bytes>",
		"opaque; Secure":   "<6 bytes>; Secure",
		" a = xyz ;Secure": "a=<3 bytes>;Secure",
	} {
		if got := RedactSetCookie(in); got != want {
			t.Errorf("RedactSetCookie(%q) = %q, want %q", in, got, want)
		}
	}
	h := http.Header{}
	h.Add("Set-Cookie", "a=secret; Path=/")
	if got := AllHeaders(h)[0].Value; got != "a=<6 bytes>; Path=/" {
		t.Errorf("AllHeaders: %q", got)
	}
}

func TestParseAltSvc(t *testing.T) {
	alts, clear := ParseAltSvc(`h3=":443"; ma=86400, h3-29=":443"; ma=86400, h2="alt.example:8443", w%3Dx=":1"`)
	if clear {
		t.Fatal("not clear")
	}
	want := []AltSvc{
		{Protocol: "h3", Authority: ":443", MaxAge: 86400},
		{Protocol: "h3-29", Authority: ":443", MaxAge: 86400},
		{Protocol: "h2", Authority: "alt.example:8443"},
		{Protocol: "w=x", Authority: ":1"},
	}
	if !reflect.DeepEqual(alts, want) {
		t.Errorf("got %+v", alts)
	}
	if _, clear := ParseAltSvc(" clear "); !clear {
		t.Error("clear")
	}
	if !IsHTTP3("h3") || !IsHTTP3("h3-29") || IsHTTP3("h2") || IsHTTP3("h30") {
		t.Error("IsHTTP3")
	}
}

// rfc9460Vector is the "alpn=h2,h3-19 mandatory=ipv4hint,alpn ipv4hint=192.0.2.1"
// SVCB RDATA from RFC 9460 Appendix D (Figure 9).
var rfc9460Vector = []byte{
	0x00, 0x10,
	0x03, 'f', 'o', 'o', 0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'o', 'r', 'g', 0x00,
	0x00, 0x00, 0x00, 0x04, 0x00, 0x01, 0x00, 0x04,
	0x00, 0x01, 0x00, 0x09, 0x02, 'h', '2', 0x05, 'h', '3', '-', '1', '9',
	0x00, 0x04, 0x00, 0x04, 0xc0, 0x00, 0x02, 0x01,
}

// answerFor wraps HTTPS RDATA records in a DNS response to query.
func answerFor(query []byte, flags uint16, rdatas ...[]byte) []byte {
	msg := append([]byte(nil), query[:len(query)-11]...) // drop the OPT record
	binary.BigEndian.PutUint16(msg[2:], flags)
	binary.BigEndian.PutUint16(msg[6:], uint16(len(rdatas)))
	binary.BigEndian.PutUint16(msg[10:], 0)
	for _, rd := range rdatas {
		msg = append(msg, 0xC0, 0x0C, 0, typeHTTPS, 0, 1, 0, 0, 0x0E, 0x10)
		msg = binary.BigEndian.AppendUint16(msg, uint16(len(rd)))
		msg = append(msg, rd...)
	}
	return msg
}

func TestHTTPSQueryAndAnswer(t *testing.T) {
	q, err := BuildHTTPSQuery("example.com.", 0x1234)
	if err != nil {
		t.Fatal(err)
	}
	wantQ := []byte{0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 1,
		7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 65, 0, 1,
		0, 0, 41, 0x04, 0xD0, 0, 0, 0, 0, 0, 0}
	if !reflect.DeepEqual(q, wantQ) {
		t.Errorf("query bytes:\n got %x\nwant %x", q, wantQ)
	}
	if _, err := BuildHTTPSQuery("bad..name", 1); err == nil {
		t.Error("empty label accepted")
	}

	recs, err := ParseHTTPSAnswer(answerFor(q, 0x8180, rfc9460Vector), 0x1234)
	if err != nil {
		t.Fatal(err)
	}
	want := []HTTPSRecord{{Priority: 16, Target: "foo.example.org", ALPN: []string{"h2", "h3-19"}}}
	if !reflect.DeepEqual(recs, want) {
		t.Errorf("records: %+v", recs)
	}
	if _, err := ParseHTTPSAnswer(answerFor(q, 0x8183), 0x1234); err == nil || !strings.Contains(err.Error(), "NXDOMAIN") {
		t.Errorf("NXDOMAIN: %v", err)
	}
	if _, err := ParseHTTPSAnswer(answerFor(q, 0x8380), 0x1234); err != ErrTruncated {
		t.Errorf("TC bit: %v", err)
	}
	if _, err := ParseHTTPSAnswer(answerFor(q, 0x8180), 0x9999); err == nil {
		t.Error("mismatched id accepted")
	}
	bad := answerFor(q, 0x8180, rfc9460Vector[:len(rfc9460Vector)-3])
	if _, err := ParseHTTPSAnswer(bad, 0x1234); err == nil {
		t.Error("cut-short SvcParam accepted")
	}
	loop := append([]byte(nil), q[:12]...)
	binary.BigEndian.PutUint16(loop[2:], 0x8180)
	binary.BigEndian.PutUint16(loop[4:], 1)
	loop = append(loop, 0xC0, 0x0C)
	if _, err := ParseHTTPSAnswer(loop, 0x1234); err == nil {
		t.Error("pointer loop accepted")
	}
}

func TestParseResolvConf(t *testing.T) {
	text := "# comment\nsearch lan\nnameserver fe80::1%en0\nnameserver 1.1.1.1\n"
	if got := parseResolvConf(text); got != "[fe80::1]:53" {
		t.Errorf("got %q", got)
	}
	if got := parseResolvConf("search lan\n"); got != "" {
		t.Errorf("no nameserver: %q", got)
	}
}

// fakeDNS answers HTTPS queries over UDP (truncated when truncate is set)
// and over TCP on the same port.
func fakeDNS(t *testing.T, truncate bool) string {
	t.Helper()
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	udp, err := net.ListenPacket("udp", tcp.Addr().String())
	if err != nil {
		tcp.Close()
		t.Skipf("cannot bind UDP on the TCP port: %v", err)
	}
	t.Cleanup(func() { tcp.Close(); udp.Close() })
	go func() {
		buf := make([]byte, 512)
		for {
			n, addr, err := udp.ReadFrom(buf)
			if err != nil {
				return
			}
			flags := uint16(0x8180)
			if truncate {
				flags = 0x8380
			}
			_, _ = udp.WriteTo(answerFor(buf[:n], flags), addr)
		}
	}()
	go func() {
		for {
			conn, err := tcp.Accept()
			if err != nil {
				return
			}
			var size [2]byte
			if _, err := readFull(conn, size[:]); err == nil {
				q := make([]byte, binary.BigEndian.Uint16(size[:]))
				if _, err := readFull(conn, q); err == nil {
					a := answerFor(q, 0x8180, rfc9460Vector)
					_, _ = conn.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(a))), a...))
				}
			}
			conn.Close()
		}
	}()
	return tcp.Addr().String()
}

func TestLookupHTTPSOverUDPAndTCP(t *testing.T) {
	ctx := context.Background()
	recs, err := LookupHTTPS(ctx, fakeDNS(t, false), "example.com", 2*time.Second)
	if err != nil || len(recs) != 0 {
		t.Errorf("UDP, no records: %+v %v", recs, err)
	}
	recs, err = LookupHTTPS(ctx, fakeDNS(t, true), "example.com", 2*time.Second)
	if err != nil || len(recs) != 1 || recs[0].ALPN[1] != "h3-19" {
		t.Errorf("TCP fallback: %+v %v", recs, err)
	}

	info := CheckHTTP3(ctx, []string{`h2=":443"`}, "https://example.com/", fakeDNS(t, true), 2*time.Second)
	if !info.Advertised || len(info.HTTPSRecords) != 1 || info.DNSError != "" || info.QueryName != "example.com" {
		t.Errorf("CheckHTTP3 via DNS: %+v", info)
	}
	info = CheckHTTP3(ctx, []string{"clear"}, "https://127.0.0.1/", "192.0.2.1:53", time.Second)
	if info.Advertised || !info.AltSvcClear || info.DNSServer != "" {
		t.Errorf("IP host skips DNS: %+v", info)
	}
}

// svcb builds HTTPS RDATA: priority, an uncompressed target, and params.
func svcb(priority uint16, target string, params ...[]byte) []byte {
	out := binary.BigEndian.AppendUint16(nil, priority)
	if target != "." {
		for _, l := range strings.Split(target, ".") {
			out = append(out, byte(len(l)))
			out = append(out, l...)
		}
	}
	out = append(out, 0)
	for _, p := range params {
		out = append(out, p...)
	}
	return out
}

func param(key uint16, value ...byte) []byte {
	out := binary.BigEndian.AppendUint16(nil, key)
	out = binary.BigEndian.AppendUint16(out, uint16(len(value)))
	return append(out, value...)
}

func TestMalformedRRsetIsRejected(t *testing.T) {
	q, _ := BuildHTTPSQuery("example.com", 7)
	alpnH3 := param(1, 2, 'h', '3')
	cases := map[string][]byte{
		"keys out of order":   svcb(1, ".", param(3, 1, 187), alpnH3),
		"repeated key":        svcb(1, ".", alpnH3, param(1, 2, 'h', '2')),
		"bad port length":     svcb(1, ".", param(3, 1)),
		"empty alpn":          svcb(1, ".", param(1)),
		"no-default-alpn val": svcb(1, ".", param(2, 1)),
		"ipv4hint length":     svcb(1, ".", param(4, 1, 2, 3)),
		"compressed target":   {0, 1, 0xC0, 0x0C},
		"target past rdata":   {0, 1},
	}
	for name, rd := range cases {
		good := svcb(2, ".", alpnH3)
		_, err := ParseHTTPSAnswer(answerFor(q, 0x8180, good, rd), 7)
		if err == nil || !strings.Contains(err.Error(), "malformed HTTPS RRset") {
			t.Errorf("%s: %v", name, err)
		}
	}
	recs, err := ParseHTTPSAnswer(answerFor(q, 0x8180, svcb(1, "svc.example.net", param(0, 0, 1), alpnH3, param(2), param(3, 0x20, 0xFB))), 7)
	if err != nil || len(recs) != 1 || recs[0].Port != 8443 || !recs[0].NoDefaultALPN || recs[0].Target != "svc.example.net" {
		t.Errorf("well-formed record: %+v %v", recs, err)
	}
}

func TestHTTPSQueryName(t *testing.T) {
	for in, want := range map[string]string{
		"https://example.com/":       "example.com",
		"https://example.com:443/x":  "example.com",
		"https://example.com:8443/":  "_8443._https.example.com",
		"http://example.com/":        "example.com",
		"http://example.com:80/":     "example.com",
		"http://example.com:8080/":   "_8080._https.example.com",
		"https://192.0.2.1/":         "",
		"https://[2001:db8::1]:443/": "",
	} {
		if got := HTTPSQueryName(in); got != want {
			t.Errorf("HTTPSQueryName(%q) = %q, want %q", in, got, want)
		}
	}
}

// zoneDNS answers HTTPS queries over UDP from a map of owner name to RDATA.
func zoneDNS(t *testing.T, zone map[string][][]byte) string {
	t.Helper()
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { udp.Close() })
	go func() {
		buf := make([]byte, 512)
		for {
			n, addr, err := udp.ReadFrom(buf)
			if err != nil {
				return
			}
			name, _, err := readName(buf[:n], 12)
			if err != nil {
				return
			}
			_, _ = udp.WriteTo(answerFor(buf[:n], 0x8180, zone[name]...), addr)
		}
	}()
	return udp.LocalAddr().String()
}

func TestAliasModeIsFollowed(t *testing.T) {
	ctx := context.Background()
	alpnH3 := param(1, 2, 'h', '3')
	server := zoneDNS(t, map[string][][]byte{
		"example.com":     {svcb(0, "cdn.example.net"), svcb(1, ".", param(1, 2, 'h', '2'))},
		"cdn.example.net": {svcb(1, ".", alpnH3)},
		"loop.example":    {svcb(0, "loop2.example")},
		"loop2.example":   {svcb(0, "loop.example")},
		"gone.example":    {svcb(0, ".")},
	})
	info := CheckHTTP3(ctx, nil, "https://example.com/", server, 2*time.Second)
	if !info.Advertised || len(info.Aliases) != 1 || info.Aliases[0] != "cdn.example.net" || info.DNSError != "" {
		t.Errorf("alias followed: %+v", info)
	}
	if _, _, err := LookupHTTPSFollowing(ctx, server, "loop.example", 2*time.Second); err == nil || !strings.Contains(err.Error(), "loop") {
		t.Errorf("loop: %v", err)
	}
	recs, _, err := LookupHTTPSFollowing(ctx, server, "gone.example", 2*time.Second)
	if err != nil || len(recs) != 0 {
		t.Errorf("alias to '.': %+v %v", recs, err)
	}
}

func TestCookieEdgeCasesFromReview(t *testing.T) {
	now := time.Date(2026, 11, 12, 0, 0, 0, 0, time.UTC)
	rejected := func(line, from string) string {
		c := ParseSetCookie(line)
		CheckCookie(&c, from, now)
		return strings.Join(c.Rejected, "|")
	}
	if r := rejected("=__Host-secret; Secure; Path=/; HttpOnly; SameSite=Lax", "https://example.com/"); !strings.Contains(r, "nameless cookie whose value starts with __Host-") {
		t.Errorf("nameless __Host- value: %q", r)
	}
	if r := rejected("a="+strings.Repeat("x", 4096), "https://example.com/"); !strings.Contains(r, "over the 4096-byte limit") {
		t.Errorf("size: %q", r)
	}
	if r := rejected("a="+strings.Repeat("x", 4095), "https://example.com/"); r != "" {
		t.Errorf("4096 bytes exactly is fine: %q", r)
	}
	if r := rejected("__Host-id=x; Secure; Path=foo", "https://example.com/"); r != "" {
		t.Errorf("Path=foo falls back to default-path /: %q", r)
	}
	if r := rejected("__Host-id=x; Secure; Path=foo", "https://example.com/a/b"); !strings.Contains(r, "Path=/") {
		t.Errorf("default-path /a is not /: %q", r)
	}
	if r := rejected("a=b\x01c", "https://example.com/"); !strings.Contains(r, "control character") {
		t.Errorf("CTL: %q", r)
	}
	c := ParseSetCookie("a=1; Max-Age=9223372036854775807; Secure; HttpOnly; SameSite=Lax")
	CheckCookie(&c, "https://example.com/", now)
	if !strings.Contains(strings.Join(c.Warnings, "|"), "over 400 days") {
		t.Errorf("huge Max-Age: %q", c.Warnings)
	}
}
