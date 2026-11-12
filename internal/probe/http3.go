package probe

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// AltSvc is one alternative from an Alt-Svc header (RFC 7838 Section 3).
type AltSvc struct {
	Protocol  string `json:"protocol"`  // ALPN id, such as "h3"
	Authority string `json:"authority"` // "[host]:port"
	MaxAge    int64  `json:"max_age,omitempty"`
}

// HTTPSRecord is the part of a DNS HTTPS record (RFC 9460) httppeek shows.
type HTTPSRecord struct {
	Priority      uint16   `json:"priority"` // 0 is AliasMode
	Target        string   `json:"target"`
	ALPN          []string `json:"alpn"`
	NoDefaultALPN bool     `json:"no_default_alpn"`
	Port          uint16   `json:"port,omitempty"`
}

// HTTP3Info says whether, and how, the final host advertises HTTP/3.
// httppeek itself does not speak QUIC: this is what a browser would learn
// before trying HTTP/3.
type HTTP3Info struct {
	AltSvc       []AltSvc      `json:"alt_svc"`
	AltSvcClear  bool          `json:"alt_svc_clear"`
	QueryName    string        `json:"query_name,omitempty"` // owner name of the HTTPS RR asked for
	Aliases      []string      `json:"aliases"`              // AliasMode targets followed, in order
	HTTPSRecords []HTTPSRecord `json:"https_records"`
	DNSServer    string        `json:"dns_server,omitempty"`
	DNSError     string        `json:"dns_error,omitempty"`
	Advertised   bool          `json:"advertised"`
}

// ParseAltSvc parses an Alt-Svc field value. "clear" yields clear=true and
// no alternatives. Malformed entries are skipped.
func ParseAltSvc(value string) (alts []AltSvc, clear bool) {
	value = strings.TrimSpace(value)
	if value == "clear" {
		return nil, true
	}
	for _, entry := range splitOutsideQuotes(value, ',') {
		parts := splitOutsideQuotes(entry, ';')
		proto, auth, ok := strings.Cut(strings.TrimSpace(parts[0]), "=")
		if !ok || proto == "" {
			continue
		}
		alt := AltSvc{Protocol: percentDecode(strings.TrimSpace(proto)), Authority: unquote(strings.TrimSpace(auth))}
		for _, p := range parts[1:] {
			k, v, _ := strings.Cut(strings.TrimSpace(p), "=")
			if strings.EqualFold(strings.TrimSpace(k), "ma") {
				if n, err := strconv.ParseInt(unquote(strings.TrimSpace(v)), 10, 64); err == nil {
					alt.MaxAge = n
				}
			}
		}
		alts = append(alts, alt)
	}
	return alts, false
}

func splitOutsideQuotes(s string, sep byte) []string {
	var out []string
	inQuote, escaped, start := false, false, 0
	for i := 0; i < len(s); i++ {
		switch {
		case escaped:
			escaped = false
		case s[i] == '\\' && inQuote:
			escaped = true
		case s[i] == '"':
			inQuote = !inQuote
		case s[i] == sep && !inQuote:
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return append(out, s[start:])
}

func unquote(s string) string {
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		s = s[1 : len(s)-1]
		var b strings.Builder
		for i := 0; i < len(s); i++ {
			if s[i] == '\\' && i+1 < len(s) {
				i++
			}
			b.WriteByte(s[i])
		}
		return b.String()
	}
	return s
}

func percentDecode(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			if n, err := strconv.ParseUint(s[i+1:i+3], 16, 8); err == nil {
				b.WriteByte(byte(n))
				i += 2
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// IsHTTP3 reports whether an ALPN id names HTTP/3 (final "h3" or a draft
// version such as "h3-29").
func IsHTTP3(alpn string) bool {
	return alpn == "h3" || strings.HasPrefix(alpn, "h3-")
}

const typeHTTPS = 65

// BuildHTTPSQuery builds a DNS query for the HTTPS record of name, with
// recursion desired and an EDNS0 OPT record advertising a 1232-byte payload.
func BuildHTTPSQuery(name string, id uint16) ([]byte, error) {
	msg := make([]byte, 12, 64)
	binary.BigEndian.PutUint16(msg[0:], id)
	binary.BigEndian.PutUint16(msg[2:], 0x0100) // RD
	binary.BigEndian.PutUint16(msg[4:], 1)      // QDCOUNT
	binary.BigEndian.PutUint16(msg[10:], 1)     // ARCOUNT (OPT)
	name = strings.TrimSuffix(name, ".")
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 {
			return nil, fmt.Errorf("invalid DNS name %q", name)
		}
		msg = append(msg, byte(len(label)))
		msg = append(msg, label...)
	}
	msg = append(msg, 0, 0, typeHTTPS, 0, 1) // root, QTYPE=65, QCLASS=IN
	// OPT: root name, TYPE 41, CLASS = UDP payload size, TTL 0, RDLEN 0.
	msg = append(msg, 0, 0, 41, 0x04, 0xD0, 0, 0, 0, 0, 0, 0)
	return msg, nil
}

// ErrTruncated means a UDP answer had the TC bit set.
var ErrTruncated = errors.New("DNS answer truncated")

// ParseHTTPSAnswer reads the HTTPS records from a DNS response to the query
// with the given id.
func ParseHTTPSAnswer(msg []byte, id uint16) ([]HTTPSRecord, error) {
	if len(msg) < 12 {
		return nil, errors.New("DNS answer too short")
	}
	if binary.BigEndian.Uint16(msg[0:]) != id {
		return nil, errors.New("DNS answer for a different query")
	}
	flags := binary.BigEndian.Uint16(msg[2:])
	if flags&0x0200 != 0 {
		return nil, ErrTruncated
	}
	switch rcode := flags & 0x000F; rcode {
	case 0:
	case 3:
		return nil, errors.New("no such domain (NXDOMAIN)")
	default:
		return nil, fmt.Errorf("DNS error code %d", rcode)
	}
	qd := int(binary.BigEndian.Uint16(msg[4:]))
	an := int(binary.BigEndian.Uint16(msg[6:]))
	off := 12
	for i := 0; i < qd; i++ {
		_, next, err := readName(msg, off)
		if err != nil {
			return nil, err
		}
		off = next + 4
	}
	records := []HTTPSRecord{}
	var malformed error
	for i := 0; i < an; i++ {
		_, next, err := readName(msg, off)
		if err != nil {
			return nil, err
		}
		if next+10 > len(msg) {
			return nil, errors.New("DNS answer cut short")
		}
		rtype := binary.BigEndian.Uint16(msg[next:])
		rdlen := int(binary.BigEndian.Uint16(msg[next+8:]))
		start := next + 10
		end := start + rdlen
		if end > len(msg) {
			return nil, errors.New("DNS record cut short")
		}
		if rtype == typeHTTPS {
			rec, err := parseHTTPSRData(msg, start, end)
			if err != nil && malformed == nil {
				malformed = err
			}
			records = append(records, rec)
		}
		off = end
	}
	if malformed != nil {
		// RFC 9460 Section 2.2: one malformed RR rejects the whole RRset.
		return nil, fmt.Errorf("malformed HTTPS RRset, ignored as a client would: %w", malformed)
	}
	return records, nil
}

// parseHTTPSRData parses one HTTPS RDATA and enforces the rules of RFC 9460
// Section 2.2: an uncompressed TargetName inside the RDATA, SvcParamKeys in
// strictly increasing order, and well-formed values for the known keys.
func parseHTTPSRData(msg []byte, start, end int) (HTTPSRecord, error) {
	var rec HTTPSRecord
	if start+2 > end {
		return rec, errors.New("HTTPS record too short")
	}
	rec.Priority = binary.BigEndian.Uint16(msg[start:])
	target, off, err := readPlainName(msg[:end], start+2)
	if err != nil {
		return rec, fmt.Errorf("TargetName: %w", err)
	}
	rec.Target = target
	rec.ALPN = []string{}
	lastKey := -1
	for off < end {
		if off+4 > end {
			return rec, errors.New("SvcParam cut short")
		}
		key := int(binary.BigEndian.Uint16(msg[off:]))
		length := int(binary.BigEndian.Uint16(msg[off+2:]))
		vStart, vEnd := off+4, off+4+length
		if vEnd > end {
			return rec, errors.New("SvcParam value cut short")
		}
		if key <= lastKey {
			return rec, fmt.Errorf("SvcParamKey %d out of order or repeated", key)
		}
		lastKey = key
		value := msg[vStart:vEnd]
		switch key {
		case 0: // mandatory: a non-empty list of 2-byte keys
			if len(value) == 0 || len(value)%2 != 0 {
				return rec, errors.New("malformed mandatory SvcParam")
			}
		case 1: // alpn: a non-empty list of length-prefixed ids
			if len(value) == 0 {
				return rec, errors.New("empty alpn SvcParam")
			}
			for i := 0; i < len(value); {
				n := int(value[i])
				if n == 0 || i+1+n > len(value) {
					return rec, errors.New("malformed alpn SvcParam")
				}
				rec.ALPN = append(rec.ALPN, string(value[i+1:i+1+n]))
				i += 1 + n
			}
		case 2: // no-default-alpn: empty
			if len(value) != 0 {
				return rec, errors.New("malformed no-default-alpn SvcParam")
			}
			rec.NoDefaultALPN = true
		case 3: // port: 2 bytes
			if len(value) != 2 {
				return rec, errors.New("malformed port SvcParam")
			}
			rec.Port = binary.BigEndian.Uint16(value)
		case 4: // ipv4hint: one or more 4-byte addresses
			if len(value) == 0 || len(value)%4 != 0 {
				return rec, errors.New("malformed ipv4hint SvcParam")
			}
		case 6: // ipv6hint: one or more 16-byte addresses
			if len(value) == 0 || len(value)%16 != 0 {
				return rec, errors.New("malformed ipv6hint SvcParam")
			}
		}
		off = vEnd
	}
	return rec, nil
}

// readPlainName reads an uncompressed domain name at off that must end
// within msg, as SVCB TargetNames are (RFC 9460 Section 2.2).
func readPlainName(msg []byte, off int) (string, int, error) {
	var labels []string
	total := 1
	for {
		if off >= len(msg) {
			return "", 0, errors.New("name runs past the record")
		}
		n := int(msg[off])
		if n == 0 {
			name := strings.Join(labels, ".")
			if name == "" {
				name = "."
			}
			return name, off + 1, nil
		}
		if n&0xC0 != 0 {
			return "", 0, errors.New("compressed or unsupported label")
		}
		if off+1+n > len(msg) {
			return "", 0, errors.New("label runs past the record")
		}
		total += 1 + n
		if total > 255 {
			return "", 0, errors.New("name longer than 255 octets")
		}
		labels = append(labels, string(msg[off+1:off+1+n]))
		off += 1 + n
	}
}

// readName reads a possibly compressed domain name at off and returns it
// with the offset just past it (in the original position).
func readName(msg []byte, off int) (string, int, error) {
	var labels []string
	next := -1
	for jumps := 0; ; {
		if off >= len(msg) {
			return "", 0, errors.New("DNS name runs past the message")
		}
		n := int(msg[off])
		switch {
		case n == 0:
			if next < 0 {
				next = off + 1
			}
			name := strings.Join(labels, ".")
			if name == "" {
				name = "."
			}
			return name, next, nil
		case n&0xC0 == 0xC0:
			if off+1 >= len(msg) {
				return "", 0, errors.New("DNS pointer cut short")
			}
			if next < 0 {
				next = off + 2
			}
			jumps++
			if jumps > 32 {
				return "", 0, errors.New("DNS name pointer loop")
			}
			off = int(binary.BigEndian.Uint16(msg[off:]) & 0x3FFF)
		case n&0xC0 != 0:
			return "", 0, errors.New("unsupported DNS label type")
		default:
			if off+1+n > len(msg) {
				return "", 0, errors.New("DNS label cut short")
			}
			labels = append(labels, string(msg[off+1:off+1+n]))
			off += 1 + n
		}
	}
}

// SystemNameserver returns the first nameserver in /etc/resolv.conf as
// "host:53", or "" when there is none (Windows, or an empty file).
func SystemNameserver() string {
	data, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return ""
	}
	return parseResolvConf(string(data))
}

func parseResolvConf(text string) string {
	for _, line := range strings.Split(text, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "nameserver" {
			host := fields[1]
			if i := strings.IndexByte(host, '%'); i >= 0 {
				host = host[:i] // drop an IPv6 zone
			}
			return net.JoinHostPort(host, "53")
		}
	}
	return ""
}

// LookupHTTPS asks server ("host:port") for the HTTPS records of name over
// UDP, retrying over TCP when the answer is truncated.
func LookupHTTPS(ctx context.Context, server, name string, timeout time.Duration) ([]HTTPSRecord, error) {
	id := uint16(time.Now().UnixNano())
	query, err := BuildHTTPSQuery(name, id)
	if err != nil {
		return nil, err
	}
	dialer := net.Dialer{Timeout: timeout}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	conn, err := dialer.DialContext(ctx, "udp", server)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	if _, err := conn.Write(query); err != nil {
		return nil, err
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	records, err := ParseHTTPSAnswer(buf[:n], id)
	if !errors.Is(err, ErrTruncated) {
		return records, err
	}

	tcp, err := dialer.DialContext(ctx, "tcp", server)
	if err != nil {
		return nil, err
	}
	defer tcp.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = tcp.SetDeadline(deadline)
	}
	framed := binary.BigEndian.AppendUint16(nil, uint16(len(query)))
	if _, err := tcp.Write(append(framed, query...)); err != nil {
		return nil, err
	}
	var size [2]byte
	if _, err := readFull(tcp, size[:]); err != nil {
		return nil, err
	}
	answer := make([]byte, binary.BigEndian.Uint16(size[:]))
	if _, err := readFull(tcp, answer); err != nil {
		return nil, err
	}
	return ParseHTTPSAnswer(answer, id)
}

func readFull(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// HTTPSQueryName is the owner name of the HTTPS RR for a URL (RFC 9460
// Section 9.1): the host for https on port 443, else "_PORT._https.host".
// An http URL is first turned into https, with port 80 becoming 443
// (Section 9.5). It returns "" for an IP-literal host.
func HTTPSQueryName(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	host := u.Hostname()
	if host == "" || net.ParseIP(host) != nil {
		return ""
	}
	port := u.Port()
	switch {
	case port == "":
		port = "443"
	case u.Scheme == "http" && port == "80":
		port = "443"
	}
	if port == "443" {
		return host
	}
	return "_" + port + "._https." + host
}

// maxAliasHops bounds how many AliasMode records are followed.
const maxAliasHops = 8

// LookupHTTPSFollowing looks up the HTTPS RRset of qname and follows
// AliasMode records (priority 0) to their targets, as RFC 9460 Section 2.4.2
// describes. It returns the ServiceMode records found and the alias chain.
// An AliasMode target of "." means the service is not available.
func LookupHTTPSFollowing(ctx context.Context, server, qname string, timeout time.Duration) ([]HTTPSRecord, []string, error) {
	aliases := []string{}
	seen := map[string]bool{strings.ToLower(qname): true}
	for {
		records, err := LookupHTTPS(ctx, server, qname, timeout)
		if err != nil {
			return nil, aliases, err
		}
		var alias *HTTPSRecord
		service := []HTTPSRecord{}
		for i := range records {
			if records[i].Priority == 0 {
				if alias == nil {
					alias = &records[i]
				}
			} else {
				service = append(service, records[i])
			}
		}
		// With an AliasMode record present, ServiceMode records in the same
		// RRset are ignored (RFC 9460 Section 2.4.2).
		if alias == nil {
			return service, aliases, nil
		}
		if alias.Target == "." {
			return []HTTPSRecord{}, aliases, nil
		}
		next := strings.ToLower(alias.Target)
		if seen[next] {
			return nil, aliases, fmt.Errorf("AliasMode loop at %s", alias.Target)
		}
		if len(aliases) >= maxAliasHops {
			return nil, aliases, fmt.Errorf("more than %d AliasMode hops", maxAliasHops)
		}
		seen[next] = true
		aliases = append(aliases, alias.Target)
		qname = alias.Target
	}
}

// CheckHTTP3 combines the final response's Alt-Svc header with the HTTPS
// records for finalURL. dnsServer "" skips the DNS lookup.
func CheckHTTP3(ctx context.Context, altSvc []string, finalURL, dnsServer string, timeout time.Duration) HTTP3Info {
	info := HTTP3Info{AltSvc: []AltSvc{}, Aliases: []string{}, HTTPSRecords: []HTTPSRecord{}}
	for _, v := range altSvc {
		alts, clear := ParseAltSvc(v)
		if clear {
			info.AltSvcClear = true
		}
		info.AltSvc = append(info.AltSvc, alts...)
	}
	for _, a := range info.AltSvc {
		if IsHTTP3(a.Protocol) {
			info.Advertised = true
		}
	}
	qname := HTTPSQueryName(finalURL)
	if dnsServer != "" && qname != "" {
		info.DNSServer = dnsServer
		info.QueryName = qname
		records, aliases, err := LookupHTTPSFollowing(ctx, dnsServer, qname, timeout)
		info.Aliases = aliases
		if err != nil {
			info.DNSError = err.Error()
		} else {
			info.HTTPSRecords = records
		}
		for _, r := range info.HTTPSRecords {
			for _, a := range r.ALPN {
				if IsHTTP3(a) {
					info.Advertised = true
				}
			}
		}
	}
	return info
}
