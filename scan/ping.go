package scan

import (
	"context"
	"net/netip"
	"time"
)

// pinger sends ICMP echo requests.
type pinger interface {
	// Ping reports whether ip answered an echo request within timeout,
	// and how long the answer took.
	Ping(ctx context.Context, ip netip.Addr, timeout time.Duration) (time.Duration, bool)
	Close()
}

// noPinger stands in where the system lets the app send no ICMP: hosts are
// then found by TCP and ARP alone.
type noPinger struct{}

func (noPinger) Ping(context.Context, netip.Addr, time.Duration) (time.Duration, bool) {
	return 0, false
}
func (noPinger) Close() {}
