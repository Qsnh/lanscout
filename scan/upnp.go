package scan

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/xml"
	"html"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/net/ipv4"
	"golang.org/x/text/encoding/simplifiedchinese"
)

// upnpDevice is what a host says of itself over UPnP.
type upnpDevice struct {
	Name, Maker, Model string
	Server             string // the SERVER header, e.g. "Linux/4.9 UPnP/1.0 …"
}

// discoverSSDP multicasts an SSDP search from the interface ifc and
// collects the answers for wait: the hosts that answer, and the
// description each one's LOCATION points to.
func discoverSSDP(ctx context.Context, ifc Interface, prefix netip.Prefix, wait time.Duration) map[netip.Addr]upnpDevice {
	found := map[netip.Addr]upnpDevice{}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: ifc.IP.AsSlice()})
	if err != nil {
		return found
	}
	defer conn.Close()
	if nif, err := net.InterfaceByIndex(ifc.Index); err == nil {
		ipv4.NewPacketConn(conn).SetMulticastInterface(nif)
	}
	group := &net.UDPAddr{IP: net.IPv4(239, 255, 255, 250), Port: 1900}
	for _, st := range []string{"ssdp:all", "upnp:rootdevice"} {
		req := "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: " + st + "\r\n\r\n"
		conn.WriteTo([]byte(req), group)
	}

	locations := map[netip.Addr]string{}
	deadline := time.Now().Add(wait)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	conn.SetReadDeadline(deadline)
	buf := make([]byte, 2048)
	for ctx.Err() == nil {
		n, from, err := conn.ReadFromUDP(buf)
		if err != nil {
			break
		}
		ip, ok := netip.AddrFromSlice(from.IP.To4())
		if !ok || !prefix.Contains(ip) {
			continue
		}
		resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(buf[:n])), nil)
		if err != nil {
			continue
		}
		d := found[ip]
		if d.Server == "" {
			d.Server = resp.Header.Get("Server")
		}
		found[ip] = d
		// The root device's description names the device as a whole.
		loc := resp.Header.Get("Location")
		if loc != "" && (locations[ip] == "" || strings.Contains(strings.ToLower(resp.Header.Get("St")), "rootdevice")) {
			locations[ip] = loc
		}
	}

	type described struct {
		ip netip.Addr
		d  upnpDevice
	}
	results := make(chan described, len(locations))
	for ip, loc := range locations {
		d := found[ip] // read here: the loop below writes found
		go func() {
			if desc, ok := fetchDescription(ctx, ip, loc); ok {
				d.Name, d.Maker, d.Model = desc.Name, desc.Maker, desc.Model
			}
			results <- described{ip, d}
		}()
	}
	for range locations {
		r := <-results
		found[r.ip] = r.d
	}
	return found
}

// fetchDescription reads the device description at loc, which must be on
// ip itself.
func fetchDescription(ctx context.Context, ip netip.Addr, loc string) (upnpDevice, bool) {
	u, err := url.Parse(loc)
	if err != nil || u.Hostname() != ip.String() {
		return upnpDevice{}, false
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, loc, nil)
	if err != nil {
		return upnpDevice{}, false
	}
	resp, err := webClient.Do(req)
	if err != nil {
		return upnpDevice{}, false
	}
	defer resp.Body.Close()
	var root struct {
		Device struct {
			FriendlyName string `xml:"friendlyName"`
			Manufacturer string `xml:"manufacturer"`
			ModelName    string `xml:"modelName"`
		} `xml:"device"`
	}
	if err := xml.NewDecoder(io.LimitReader(resp.Body, 256<<10)).Decode(&root); err != nil {
		return upnpDevice{}, false
	}
	d := root.Device
	return upnpDevice{
		Name:  strings.TrimSpace(d.FriendlyName),
		Maker: strings.TrimSpace(d.Manufacturer),
		Model: strings.TrimSpace(d.ModelName),
	}, true
}

// webClient fetches from devices of the LAN, whose certificates are their
// own, and follows redirects only on the device.
var webClient = &http.Client{
	Transport: &http.Transport{
		Proxy:               nil,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		DialContext:         (&net.Dialer{Timeout: 2 * time.Second}).DialContext,
		TLSHandshakeTimeout: 2 * time.Second,
		DisableKeepAlives:   true,
	},
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 3 || req.URL.Hostname() != via[0].URL.Hostname() {
			return http.ErrUseLastResponse
		}
		return nil
	},
}

var titlePattern = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

// uselessTitle matches the titles of error pages and placeholders, which
// tell nothing of the device.
var uselessTitle = regexp.MustCompile(`(?i)not found|error|forbidden|unauthori[sz]ed|bad request|moved|redirect|^\d{3}\b|^index of|^untitled|^document$|^home$|^web$|^loading|^welcome$|^login$|^登录$|^首页$`)

// webInfo fetches the home page of ip's web server on port, for its title
// and its Server header, which name routers, printers, cameras and NASes.
func webInfo(ctx context.Context, ip netip.Addr, port int) (title, server string) {
	scheme := "http"
	if port == 443 || port == 8443 || port == 5001 {
		scheme = "https"
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	u := url.URL{Scheme: scheme, Host: netip.AddrPortFrom(ip, uint16(port)).String(), Path: "/"}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", ""
	}
	req.Header.Set("User-Agent", "LanScout/1.0")
	resp, err := webClient.Do(req)
	if err != nil {
		return "", ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if m := titlePattern.FindSubmatch(body); m != nil {
		raw := m[1]
		if !utf8.Valid(raw) {
			// Pages of Chinese routers and cameras are often in GBK.
			if b, err := simplifiedchinese.GBK.NewDecoder().Bytes(raw); err == nil {
				raw = b
			}
		}
		title = strings.Join(strings.Fields(html.UnescapeString(string(raw))), " ")
		if len([]rune(title)) > 60 {
			title = string([]rune(title)[:60]) + "…"
		}
		if uselessTitle.MatchString(title) {
			title = ""
		}
	}
	return title, resp.Header.Get("Server")
}
