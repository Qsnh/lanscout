// Command lanscan scans the local network from a terminal and prints the
// devices found, as LanScout's window shows them.
//
//	go run ./cmd/lanscan [-net 192.168.1.0/24] [-if en0]
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/Qsnh/lanscout/scan"
)

func main() {
	network := flag.String("net", "", "the network to scan, e.g. 192.168.1.0/24 (default: the interface's)")
	ifName := flag.String("if", "", "the interface to scan from (default: the default route's)")
	flag.Parse()

	ifs, err := scan.Interfaces()
	if err != nil {
		log.Fatal(err)
	}
	ifc := ifs[0]
	for _, i := range ifs {
		if i.Name == *ifName {
			ifc = i
		}
	}
	opts := scan.Options{Interface: ifc}
	if *network != "" {
		if opts.Prefix, err = scan.ParsePrefix(*network); err != nil {
			log.Fatal(err)
		}
	} else {
		opts.Prefix = scan.ScanPrefix(ifc)
	}
	fmt.Fprintf(os.Stderr, "扫描 %s，经由 %s，网关 %s\n", opts.Prefix, ifc, ifc.Gateway)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	start := time.Now()
	devices := scan.Run(ctx, opts, scan.Callbacks{
		Progress: func(p scan.Progress) {
			fmt.Fprintf(os.Stderr, "\r%s %d/%d (%3.0f%%)   ", p.Phase, p.Done, p.Total, p.Fraction*100)
		},
	})
	fmt.Fprintf(os.Stderr, "\n%d 台设备，用时 %s\n\n", len(devices), time.Since(start).Round(100*time.Millisecond))

	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "IP\tMAC\t厂商\t名称\t类型\t系统\t端口\t延迟\t发现方式")
	for _, d := range devices {
		mac := d.MAC
		if d.RandomMAC {
			mac += " (随机)"
		}
		kind := d.Kind.Label()
		if d.IsSelf {
			kind += " (本机)"
		}
		rtt := ""
		if d.RTT > 0 {
			rtt = d.RTT.Round(100 * time.Microsecond).String()
		}
		name := d.Name()
		if d.Model != "" {
			name += " [" + d.Model + "]"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", d.IP, mac, scan.Brand(d.Vendor), name, kind, d.OS, scan.FormatPorts(d.Ports), rtt, strings.Join(d.Via, ","))
	}
	w.Flush()
}
