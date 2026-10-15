package scan

import (
	"context"
	"encoding/binary"
	"net/netip"
	"syscall"
	"time"
	"unsafe"
)

var (
	procIcmpCreateFile  = iphlpapi.NewProc("IcmpCreateFile")
	procIcmpSendEcho    = iphlpapi.NewProc("IcmpSendEcho")
	procIcmpCloseHandle = iphlpapi.NewProc("IcmpCloseHandle")
)

// icmpPinger pings with IP Helper's IcmpSendEcho, which needs no
// administrator rights. Each Ping blocks a thread until the reply or the
// timeout, on a handle of its own.
type icmpPinger struct{}

func newPinger() (pinger, error) {
	if err := procIcmpSendEcho.Find(); err != nil {
		return nil, err
	}
	return icmpPinger{}, nil
}

func (icmpPinger) Ping(ctx context.Context, ip netip.Addr, timeout time.Duration) (time.Duration, bool) {
	h, _, _ := procIcmpCreateFile.Call()
	if h == 0 || syscall.Handle(h) == syscall.InvalidHandle {
		return 0, false
	}
	defer procIcmpCloseHandle.Call(h)

	data := []byte("lanscout")
	// An ICMP_ECHO_REPLY (Address, Status, RoundTripTime, …), the data
	// echoed, and room for an ICMP error.
	reply := make([]byte, 128+len(data))
	a := ip.As4()
	start := time.Now()
	n, _, _ := procIcmpSendEcho.Call(h,
		uintptr(binary.LittleEndian.Uint32(a[:])), // the address in network order
		uintptr(unsafe.Pointer(&data[0])), uintptr(len(data)), 0,
		uintptr(unsafe.Pointer(&reply[0])), uintptr(len(reply)),
		uintptr(timeout.Milliseconds()))
	if n == 0 || ctx.Err() != nil {
		return 0, false
	}
	if status := binary.LittleEndian.Uint32(reply[4:]); status != 0 { // IP_SUCCESS
		return 0, false
	}
	if from := netip.AddrFrom4([4]byte(reply[0:4])); from != ip {
		return 0, false
	}
	rtt := time.Duration(binary.LittleEndian.Uint32(reply[8:])) * time.Millisecond
	if rtt == 0 {
		rtt = time.Since(start)
	}
	return rtt, true
}

func (icmpPinger) Close() {}
