package scan

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/text/encoding/simplifiedchinese"
)

// reverseDNS asks the system's resolver for the name of ip, which home
// routers answer from their DHCP leases.
func reverseDNS(ctx context.Context, ip netip.Addr) string {
	ctx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
	defer cancel()
	names, err := net.DefaultResolver.LookupAddr(ctx, ip.String())
	if err != nil || len(names) == 0 {
		return ""
	}
	return cleanHostname(names[0], ip)
}

// cleanHostname trims the trailing dot and the local domains routers add
// ("iPhone.lan", "nas.home"), and drops names that only spell the address.
func cleanHostname(name string, ip netip.Addr) string {
	name = strings.TrimSuffix(strings.TrimSpace(name), ".")
	for _, d := range []string{".local", ".lan", ".home", ".localdomain", ".home.arpa", ".router", ".domain", ".dhcp", ".internal", ".huawei.com"} {
		if strings.HasSuffix(strings.ToLower(name), d) {
			name = name[:len(name)-len(d)]
			break
		}
	}
	a := ip.As4()
	dashed := fmt.Sprintf("%d-%d-%d-%d", a[0], a[1], a[2], a[3])
	if name == "" || strings.Contains(name, ip.String()) || strings.Contains(name, dashed) {
		return ""
	}
	return name
}

// netbiosName asks ip for its NetBIOS names (a node status request to UDP
// port 137), which Windows and Samba answer, and returns the computer's.
func netbiosName(ctx context.Context, ip netip.Addr) string {
	resp, err := udpExchange(ctx, netip.AddrPortFrom(ip, 137), netbiosRequest(), 1200*time.Millisecond)
	if err != nil {
		return ""
	}
	return parseNetBIOS(resp)
}

// netbiosRequest is a node status request for the name "*".
func netbiosRequest() []byte {
	b := []byte{
		0x4c, 0x53, // transaction ID
		0x00, 0x00, // flags
		0x00, 0x01, // one question
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x20, // the encoded name's length: 32
	}
	// "*" and 15 NULs, each byte in two letters from 'A'.
	name := make([]byte, 16)
	name[0] = '*'
	for _, c := range name {
		b = append(b, 'A'+c>>4, 'A'+c&0x0f)
	}
	return append(b, 0x00, 0x00, 0x21, 0x00, 0x01) // end of name, NBSTAT, IN
}

// parseNetBIOS returns the first unique name of a workstation (suffix 0x00)
// in a node status response, else the first unique name.
func parseNetBIOS(b []byte) string {
	if len(b) < 12 || binary.BigEndian.Uint16(b[6:]) == 0 {
		return ""
	}
	i := 12
	// The name of the answer: labels, or a pointer.
	for i < len(b) {
		l := int(b[i])
		if l == 0 {
			i++
			break
		}
		if l&0xc0 == 0xc0 {
			i += 2
			break
		}
		i += 1 + l
	}
	i += 2 + 2 + 4 + 2 // type, class, TTL, data length
	if i >= len(b) {
		return ""
	}
	count := int(b[i])
	i++
	var first string
	for range count {
		if i+18 > len(b) {
			break
		}
		name := netbiosText(b[i : i+15])
		suffix := b[i+15]
		group := binary.BigEndian.Uint16(b[i+16:])&0x8000 != 0
		i += 18
		if group || name == "" || !isPrintable(name) {
			continue
		}
		if suffix == 0x00 {
			return name
		}
		if first == "" {
			first = name
		}
	}
	return first
}

// netbiosText reads a name of a node status response, in the OEM code
// page of the host: GBK for Chinese Windows.
func netbiosText(raw []byte) string {
	raw = bytes.TrimRight(raw, " \x00")
	if utf8.Valid(raw) {
		return string(raw)
	}
	dec, err := simplifiedchinese.GBK.NewDecoder().Bytes(raw)
	if err != nil {
		return ""
	}
	// The name is cut at 15 bytes, which may split its last character.
	return strings.TrimRight(string(dec), "\uFFFD")
}

func isPrintable(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// mdnsInfo asks ip itself, on the mDNS port, for the name of its address
// and for its device info, as Apple devices, Android and Linux (Avahi)
// answer a unicast query: its host name and, for Apple's, its model.
func mdnsInfo(ctx context.Context, ip netip.Addr) (name, model string) {
	q, err := mdnsQuery(ip)
	if err != nil {
		return "", ""
	}
	resp, err := udpExchange(ctx, netip.AddrPortFrom(ip, 5353), q, 1200*time.Millisecond)
	if err != nil {
		return "", ""
	}
	return parseMDNS(resp, ip)
}

func reverseName(ip netip.Addr) string {
	a := ip.As4()
	return fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa.", a[3], a[2], a[1], a[0])
}

func mdnsQuery(ip netip.Addr) ([]byte, error) {
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{})
	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	for _, q := range []struct {
		name string
		typ  dnsmessage.Type
	}{{reverseName(ip), dnsmessage.TypePTR}, {"_device-info._tcp.local.", dnsmessage.TypePTR}} {
		name, err := dnsmessage.NewName(q.name)
		if err != nil {
			return nil, err
		}
		if err := b.Question(dnsmessage.Question{Name: name, Type: q.typ, Class: dnsmessage.ClassINET}); err != nil {
			return nil, err
		}
	}
	return b.Finish()
}

// parseMDNS reads the PTR record of ip's reverse name, its host name, and
// a TXT record's "model=", in any section of an mDNS response.
func parseMDNS(msg []byte, ip netip.Addr) (name, model string) {
	var p dnsmessage.Parser
	if _, err := p.Start(msg); err != nil {
		return "", ""
	}
	if err := p.SkipAllQuestions(); err != nil {
		return "", ""
	}
	rev := strings.ToLower(reverseName(ip))
	sections := []struct {
		header func() (dnsmessage.ResourceHeader, error)
		skip   func() error
	}{
		{p.AnswerHeader, p.SkipAnswer},
		{p.AuthorityHeader, p.SkipAuthority},
		{p.AdditionalHeader, p.SkipAdditional},
	}
	for _, s := range sections {
		for {
			h, err := s.header()
			if err != nil {
				break // the section is done
			}
			switch h.Type {
			case dnsmessage.TypePTR:
				var r dnsmessage.PTRResource
				if r, err = p.PTRResource(); err == nil && name == "" && strings.ToLower(h.Name.String()) == rev {
					name = cleanHostname(r.PTR.String(), ip)
				}
			case dnsmessage.TypeTXT:
				var r dnsmessage.TXTResource
				if r, err = p.TXTResource(); err == nil {
					for _, kv := range r.TXT {
						if v, ok := strings.CutPrefix(kv, "model="); ok && model == "" {
							model = v
						}
					}
				}
			default:
				err = s.skip()
			}
			if err != nil {
				return name, model
			}
		}
	}
	return name, model
}

// udpExchange sends req to addr and returns the first reply, over a
// connected socket, whose replies the firewall lets in.
func udpExchange(ctx context.Context, addr netip.AddrPort, req []byte, timeout time.Duration) ([]byte, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "udp4", addr.String())
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	deadline := time.Now().Add(timeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	buf := make([]byte, 4096)
	// Send twice, a moment apart, for a datagram lost on Wi-Fi.
	for range 2 {
		if _, err := conn.Write(req); err != nil {
			return nil, err
		}
		read := time.Now().Add(timeout / 2)
		if read.After(deadline) {
			read = deadline
		}
		conn.SetReadDeadline(read)
		n, err := conn.Read(buf)
		if err == nil {
			return buf[:n], nil
		}
		if time.Now().After(deadline) {
			return nil, err
		}
	}
	return nil, errors.New("no reply")
}
