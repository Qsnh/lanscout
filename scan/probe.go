package scan

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"syscall"
	"time"
)

// dialTCP tries to connect to ip:port. open reports a connection; alive
// that the host is there, which a refusal shows as well as a connection.
// Windows tries again after a refusal and reports it after a second or two,
// past the timeout: there the hosts that refuse are found by ARP.
func dialTCP(ctx context.Context, ip netip.Addr, port int, timeout time.Duration) (open, alive bool, rtt time.Duration) {
	d := net.Dialer{Timeout: timeout}
	start := time.Now()
	conn, err := d.DialContext(ctx, "tcp4", netip.AddrPortFrom(ip, uint16(port)).String())
	rtt = time.Since(start)
	if err == nil {
		conn.Close()
		return true, true, rtt
	}
	if isRefused(err) {
		return false, true, rtt
	}
	return false, false, 0
}

func isRefused(err error) bool {
	if errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.ECONNRESET) {
		return true
	}
	var errno syscall.Errno
	// WSAECONNREFUSED and WSAECONNRESET, on Windows.
	return errors.As(err, &errno) && (errno == 10061 || errno == 10054)
}
