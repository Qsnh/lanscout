package scan

import (
	"bufio"
	"context"
	"net/netip"
	"os/exec"
	"strings"
	"time"
)

// readARP reads the ARP table with arp(8).
func readARP() ([]arpEntry, error) {
	out, err := run("/usr/sbin/arp", "-an")
	if err != nil {
		return nil, err
	}
	return parseARP(out), nil
}

// defaultGateway asks route(8) for the default route's next hop and its
// interface.
func defaultGateway() (netip.Addr, int) {
	out, err := run("/sbin/route", "-n", "get", "default")
	if err != nil {
		return netip.Addr{}, 0
	}
	var gw netip.Addr
	var ifName string
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		k, v, ok := strings.Cut(strings.TrimSpace(sc.Text()), ":")
		if !ok {
			continue
		}
		switch k {
		case "gateway":
			gw, _ = netip.ParseAddr(strings.TrimSpace(v))
		case "interface":
			ifName = strings.TrimSpace(v)
		}
	}
	return gw, interfaceIndex(ifName)
}

// interfaceLabels names the interfaces as System Settings does ("Wi-Fi",
// "Ethernet"), from networksetup(8).
func interfaceLabels() map[string]string {
	out, err := run("/usr/sbin/networksetup", "-listallhardwareports")
	if err != nil {
		return nil
	}
	labels := map[string]string{}
	var port string
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		line := sc.Text()
		if v, ok := strings.CutPrefix(line, "Hardware Port: "); ok {
			port = strings.TrimSpace(v)
		} else if v, ok := strings.CutPrefix(line, "Device: "); ok && port != "" {
			labels[strings.TrimSpace(v)] = port
			port = ""
		}
	}
	return labels
}

func run(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).Output()
	return string(out), err
}
