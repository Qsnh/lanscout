package scan

import (
	"net/netip"
	"regexp"
	"strings"
)

// arpEntry is a row of the system's ARP table.
type arpEntry struct {
	IP  netip.Addr
	MAC string
}

var (
	ipv4Pattern = regexp.MustCompile(`\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b`)
	macPattern  = regexp.MustCompile(`(?i)\b([0-9a-f]{1,2}([:-])[0-9a-f]{1,2}(?:[:-][0-9a-f]{1,2}){4})\b`)
)

// parseARP reads the output of arp -a, as macOS, Linux and Windows print
// it in any language: each line holding an IPv4 address and a MAC address
// is an entry. Incomplete entries, broadcast and multicast are left out.
func parseARP(out string) []arpEntry {
	var entries []arpEntry
	for _, line := range strings.Split(out, "\n") {
		ipm := ipv4Pattern.FindStringSubmatch(line)
		macm := macPattern.FindStringSubmatch(line)
		if ipm == nil || macm == nil {
			continue
		}
		ip, err := netip.ParseAddr(ipm[1])
		if err != nil {
			continue
		}
		mac := NormalizeMAC(macm[1])
		if mac == "" {
			continue
		}
		entries = append(entries, arpEntry{ip, mac})
	}
	return entries
}
