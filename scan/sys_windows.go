package scan

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"syscall"
	"time"
	"unsafe"
)

var (
	iphlpapi              = syscall.NewLazyDLL("iphlpapi.dll")
	procGetIpNetTable     = iphlpapi.NewProc("GetIpNetTable")
	procGetIpForwardTable = iphlpapi.NewProc("GetIpForwardTable")
)

const (
	errInsufficientBuffer = 122
	errNoData             = 232
)

// table calls one of IP Helper's Get…Table functions, which fill a buffer
// they say the size of, and returns the table.
func table(proc *syscall.LazyProc) ([]byte, error) {
	if err := proc.Find(); err != nil {
		return nil, err
	}
	size := uint32(0)
	r, _, _ := proc.Call(0, uintptr(unsafe.Pointer(&size)), 0)
	if r == errNoData {
		return nil, nil
	}
	if r != errInsufficientBuffer && r != 0 {
		return nil, fmt.Errorf("%s: %d", proc.Name, r)
	}
	for range 3 {
		if size == 0 {
			return nil, nil
		}
		buf := make([]byte, size)
		r, _, _ = proc.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0)
		switch r {
		case 0:
			return buf, nil
		case errNoData:
			return nil, nil
		case errInsufficientBuffer:
			continue // the table grew
		default:
			return nil, fmt.Errorf("%s: %d", proc.Name, r)
		}
	}
	return nil, errors.New(proc.Name + ": the table keeps growing")
}

// readARP reads the ARP table with GetIpNetTable, or arp -a when that
// fails. A MIB_IPNETTABLE is a count followed by rows of MIB_IPNETROW:
// dwIndex, dwPhysAddrLen, bPhysAddr[8], dwAddr, dwType, 24 bytes.
func readARP() ([]arpEntry, error) {
	buf, err := table(procGetIpNetTable)
	if err != nil {
		return readARPCommand()
	}
	if len(buf) < 4 {
		return nil, nil // the table is empty
	}
	n := int(binary.LittleEndian.Uint32(buf))
	var entries []arpEntry
	for i := range n {
		row := buf[4+i*24:]
		if len(row) < 24 {
			break
		}
		macLen := int(binary.LittleEndian.Uint32(row[4:]))
		typ := binary.LittleEndian.Uint32(row[20:])
		if macLen != 6 || typ == 2 { // 2 is MIB_IPNET_TYPE_INVALID
			continue
		}
		mac := NormalizeMAC(fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", row[8], row[9], row[10], row[11], row[12], row[13]))
		if mac == "" {
			continue
		}
		ip := netip.AddrFrom4([4]byte(row[16:20]))
		entries = append(entries, arpEntry{ip, mac})
	}
	return entries, nil
}

func readARPCommand() ([]arpEntry, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "arp", "-a")
	// No console window flashing over the app.
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000} // CREATE_NO_WINDOW
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	return parseARP(string(out)), nil
}

// defaultGateway finds the default route with the lowest metric in the
// routing table from GetIpForwardTable: a count followed by rows of
// MIB_IPFORWARDROW, 14 DWORDs: dwForwardDest, dwForwardMask,
// dwForwardPolicy, dwForwardNextHop, dwForwardIfIndex, …, dwForwardMetric1
// the tenth.
func defaultGateway() (netip.Addr, int) {
	buf, err := table(procGetIpForwardTable)
	if err != nil || len(buf) < 4 {
		return netip.Addr{}, 0
	}
	n := int(binary.LittleEndian.Uint32(buf))
	var gw netip.Addr
	index, best := 0, uint32(1<<32-1)
	for i := range n {
		row := buf[4+i*56:]
		if len(row) < 56 {
			break
		}
		dest := binary.LittleEndian.Uint32(row[0:])
		mask := binary.LittleEndian.Uint32(row[4:])
		if dest != 0 || mask != 0 {
			continue
		}
		hop := netip.AddrFrom4([4]byte(row[12:16]))
		metric := binary.LittleEndian.Uint32(row[36:])
		if hop.IsUnspecified() || metric >= best {
			continue
		}
		gw, index, best = hop, int(binary.LittleEndian.Uint32(row[16:])), metric
	}
	return gw, index
}

// interfaceLabels returns nothing: Windows names interfaces as people know
// them already ("WLAN", "以太网").
func interfaceLabels() map[string]string { return nil }
