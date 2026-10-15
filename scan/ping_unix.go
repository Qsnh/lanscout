//go:build !windows

package scan

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// icmpPinger pings over one unprivileged ICMP socket, which macOS gives
// every app and Linux the groups in net.ipv4.ping_group_range: a goroutine
// reads the replies and hands each to the Ping waiting for its sequence
// number.
type icmpPinger struct {
	conn *icmp.PacketConn
	id   int

	mu   sync.Mutex
	seq  uint16
	wait map[uint16]echoWaiter
}

type echoWaiter struct {
	ip   netip.Addr
	sent time.Time
	ch   chan time.Duration
}

func newPinger() (pinger, error) {
	c, err := icmp.ListenPacket("udp4", "0.0.0.0")
	if err != nil {
		return nil, err
	}
	p := &icmpPinger{conn: c, id: os.Getpid() & 0xffff, wait: map[uint16]echoWaiter{}}
	go p.read()
	return p, nil
}

func (p *icmpPinger) Ping(ctx context.Context, ip netip.Addr, timeout time.Duration) (time.Duration, bool) {
	ch := make(chan time.Duration, 1)
	p.mu.Lock()
	p.seq++
	seq := p.seq
	p.wait[seq] = echoWaiter{ip, time.Now(), ch}
	p.mu.Unlock()
	defer func() {
		p.mu.Lock()
		delete(p.wait, seq)
		p.mu.Unlock()
	}()

	msg := icmp.Message{Type: ipv4.ICMPTypeEcho, Body: &icmp.Echo{ID: p.id, Seq: int(seq), Data: []byte("lanscout")}}
	b, err := msg.Marshal(nil)
	if err != nil {
		return 0, false
	}
	if _, err := p.conn.WriteTo(b, &net.UDPAddr{IP: ip.AsSlice()}); err != nil {
		return 0, false
	}
	t := time.NewTimer(timeout)
	defer t.Stop()
	select {
	case rtt := <-ch:
		return rtt, true
	case <-t.C:
	case <-ctx.Done():
	}
	return 0, false
}

func (p *icmpPinger) read() {
	buf := make([]byte, 1500)
	for {
		n, peer, err := p.conn.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		m, err := icmp.ParseMessage(1, buf[:n])
		if err != nil || m.Type != ipv4.ICMPTypeEchoReply {
			continue
		}
		echo, ok := m.Body.(*icmp.Echo)
		if !ok {
			continue
		}
		var src netip.Addr
		if ua, ok := peer.(*net.UDPAddr); ok {
			src, _ = netip.AddrFromSlice(ua.IP.To4())
		}
		p.mu.Lock()
		w, ok := p.wait[uint16(echo.Seq)]
		p.mu.Unlock()
		if ok && w.ip == src {
			select {
			case w.ch <- time.Since(w.sent):
			default:
			}
		}
	}
}

func (p *icmpPinger) Close() { p.conn.Close() }
