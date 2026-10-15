//go:build !darwin && !windows

package scan

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"net/netip"
	"os"
	"strings"
)

// readARP reads Linux's ARP table from /proc/net/arp.
func readARP() ([]arpEntry, error) {
	b, err := os.ReadFile("/proc/net/arp")
	if err != nil {
		return nil, err
	}
	return parseARP(string(b)), nil
}

// defaultGateway reads Linux's default route from /proc/net/route, whose
// addresses are hexadecimal in the host's byte order.
func defaultGateway() (netip.Addr, int) {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return netip.Addr{}, 0
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 3 || fields[1] != "00000000" {
			continue
		}
		b, err := hex.DecodeString(fields[2])
		if err != nil || len(b) != 4 {
			continue
		}
		var a [4]byte
		binary.LittleEndian.PutUint32(a[:], binary.BigEndian.Uint32(b))
		return netip.AddrFrom4(a), interfaceIndex(fields[0])
	}
	return netip.Addr{}, 0
}

func interfaceLabels() map[string]string { return nil }
