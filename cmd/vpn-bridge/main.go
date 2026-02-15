package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/songgao/water"
)

// === CLI flags ===

type flags struct {
	socketPath string
	wgConfig   string
	vmCIDR     string
	gatewayIP  string
	mtu        int
}

func parseFlags() flags {
	var f flags
	flag.StringVar(&f.socketPath, "socket", "", "UDS path (seqpacket) for raw L2 frames")
	flag.StringVar(&f.wgConfig, "wg-config", "", "WireGuard config file path")
	flag.StringVar(&f.vmCIDR, "vm-ip", "", "VM IP CIDR (e.g. 10.99.0.2/24)")
	flag.StringVar(&f.gatewayIP, "gateway-ip", "", "gateway IP (e.g. 10.99.0.1)")
	flag.IntVar(&f.mtu, "mtu", 1420, "MTU")
	flag.Parse()
	return f
}

// === UDS client (seqpacket) ===

type udsClient struct {
	conn   *net.UnixConn
	remote string
}

func dialSeqpacket(remotePath string) (*udsClient, error) {
	if remotePath == "" {
		return nil, fmt.Errorf("socket path is required")
	}
	remotePath = filepath.Clean(remotePath)

	raddr := &net.UnixAddr{Name: remotePath, Net: "unixpacket"}
	conn, err := net.DialUnix("unixpacket", nil, raddr)
	if err != nil {
		return nil, fmt.Errorf("dial seqpacket %q: %w", remotePath, err)
	}

	return &udsClient{conn: conn, remote: remotePath}, nil
}

func (c *udsClient) Close() error {
	if c == nil || c.conn == nil {
		return nil
	}
	return c.conn.Close()
}

func (c *udsClient) ReadFrame(buf []byte) (int, error) {
	return c.conn.Read(buf)
}

func (c *udsClient) WriteFrame(frame []byte) error {
	_, err := c.conn.Write(frame)
	return err
}

// === Ethernet bridge ===

type macAddr [6]byte

func (m macAddr) String() string {
	b := make([]byte, 0, 17)
	for i := 0; i < 6; i++ {
		if i > 0 {
			b = append(b, ':')
		}
		x := "0123456789abcdef"
		b = append(b, x[m[i]>>4], x[m[i]&0x0f])
	}
	return string(b)
}

type bridgeState struct {
	mu      sync.RWMutex
	vmMAC   macAddr
	vmMACOK bool
}

func (s *bridgeState) setVMMAC(m macAddr) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.vmMACOK && s.vmMAC == m {
		return
	}
	s.vmMAC = m
	s.vmMACOK = true
}

func (s *bridgeState) getVMMAC() (macAddr, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.vmMAC, s.vmMACOK
}

const (
	ethHdrLen       = 14
	etherTypeIPv4   = 0x0800
	etherTypeARP    = 0x0806
	etherTypeIPv6   = 0x86DD
	arpPayloadLen   = 28
	arpOpRequest    = 1
	arpOpReply      = 2
	arpHTypeEther   = 1
	arpPTypeIPv4    = 0x0800
	arpHLenEtherMAC = 6
	arpPLenIPv4     = 4
)

func parseEthernet(frame []byte) (dst, src macAddr, etherType uint16, payload []byte, err error) {
	if len(frame) < ethHdrLen {
		return dst, src, 0, nil, fmt.Errorf("short ethernet frame: %d", len(frame))
	}
	copy(dst[:], frame[0:6])
	copy(src[:], frame[6:12])
	etherType = binary.BigEndian.Uint16(frame[12:14])
	return dst, src, etherType, frame[14:], nil
}

func ipEtherType(pkt []byte) (uint16, bool) {
	if len(pkt) < 1 {
		return 0, false
	}
	v := pkt[0] >> 4
	switch v {
	case 4:
		return etherTypeIPv4, true
	case 6:
		return etherTypeIPv6, true
	default:
		return 0, false
	}
}

func wrapEthernet(payload []byte, dst, src macAddr, etherType uint16) []byte {
	frame := make([]byte, ethHdrLen+len(payload))
	copy(frame[0:6], dst[:])
	copy(frame[6:12], src[:])
	binary.BigEndian.PutUint16(frame[12:14], etherType)
	copy(frame[14:], payload)
	return frame
}

func randomLocalMAC() (macAddr, error) {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		return macAddr{}, fmt.Errorf("rand mac: %w", err)
	}
	b[0] = (b[0] | 0x02) & 0xfe
	return macAddr(b), nil
}

// === ARP responder (IPv4 only) ===

func tryARPReply(frame []byte, gatewayIPv4 net.IP, bridgeMAC macAddr) ([]byte, bool) {
	if len(frame) < ethHdrLen+arpPayloadLen {
		return nil, false
	}
	_, _, etherType, payload, err := parseEthernet(frame)
	if err != nil || etherType != etherTypeARP {
		return nil, false
	}
	if len(payload) < arpPayloadLen {
		return nil, false
	}

	htype := binary.BigEndian.Uint16(payload[0:2])
	ptype := binary.BigEndian.Uint16(payload[2:4])
	hlen := payload[4]
	plen := payload[5]
	op := binary.BigEndian.Uint16(payload[6:8])
	if htype != arpHTypeEther || ptype != arpPTypeIPv4 || hlen != arpHLenEtherMAC || plen != arpPLenIPv4 {
		return nil, false
	}
	if op != arpOpRequest {
		return nil, false
	}

	sha := payload[8:14]
	spa := payload[14:18]
	tpa := payload[24:28]
	gip := gatewayIPv4.To4()
	if gip == nil {
		return nil, false
	}
	if !bytes.Equal(tpa, gip) {
		return nil, false
	}

	var senderMAC macAddr
	copy(senderMAC[:], sha)
	var senderIP [4]byte
	copy(senderIP[:], spa)

	arp := make([]byte, arpPayloadLen)
	binary.BigEndian.PutUint16(arp[0:2], arpHTypeEther)
	binary.BigEndian.PutUint16(arp[2:4], arpPTypeIPv4)
	arp[4] = arpHLenEtherMAC
	arp[5] = arpPLenIPv4
	binary.BigEndian.PutUint16(arp[6:8], arpOpReply)
	copy(arp[8:14], bridgeMAC[:])
	copy(arp[14:18], gip)
	copy(arp[18:24], senderMAC[:])
	copy(arp[24:28], senderIP[:])

	return wrapEthernet(arp, senderMAC, bridgeMAC, etherTypeARP), true
}

// === DHCP (stub) ===

func dhcpStubLog() {
	// TODO: DHCP not implemented. VM must be statically configured.
	log.Printf("dhcp: not implemented; VM must be statically configured")
}

// === Tun device (L3) ===

type tunDevice interface {
	Read([]byte) (int, error)
	Write([]byte) (int, error)
	Close() error
	Name() string
}

func createTUN(mtu int) (*water.Interface, string, error) {
	cfg := water.Config{DeviceType: water.TUN}
	ifce, err := water.New(cfg)
	if err != nil {
		return nil, "", fmt.Errorf("create tun: %w", err)
	}
	name := ifce.Name()
	if err := setLinkMTUUp(name, mtu); err != nil {
		_ = ifce.Close()
		return nil, "", err
	}
	return ifce, name, nil
}

func setLinkMTUUp(ifName string, mtu int) error {
	if ifName == "" {
		return fmt.Errorf("interface name is empty")
	}
	if mtu <= 0 {
		return fmt.Errorf("invalid mtu: %d", mtu)
	}

	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "linux":
		cmd = exec.Command("ip", "link", "set", "dev", ifName, "mtu", strconv.Itoa(mtu), "up")
	case "darwin":
		cmd = exec.Command("ifconfig", ifName, "mtu", strconv.Itoa(mtu), "up")
	default:
		return fmt.Errorf("unsupported OS for MTU setup: %s", runtime.GOOS)
	}

	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			return fmt.Errorf("set mtu/up for %s: %w", ifName, err)
		}
		return fmt.Errorf("set mtu/up for %s: %w: %s", ifName, err, msg)
	}
	return nil
}

// === WireGuard integration (stub; delegates to system tools) ===

type wgPeer struct {
	PublicKey  string
	Endpoint   string
	AllowedIPs []string
}

type wgConfig struct {
	PrivateKey string
	Peers      []wgPeer
}

func parseWGConfig(path string) (wgConfig, error) {
	f, err := os.Open(path)
	if err != nil {
		return wgConfig{}, fmt.Errorf("open wg config: %w", err)
	}
	defer f.Close()

	var out wgConfig
	var curSection string
	var curPeer *wgPeer

	s := bufio.NewScanner(f)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			sec := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(line, "["), "]"))
			curSection = strings.ToLower(sec)
			switch curSection {
			case "peer":
				out.Peers = append(out.Peers, wgPeer{})
				curPeer = &out.Peers[len(out.Peers)-1]
			default:
				curPeer = nil
			}
			continue
		}

		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.ToLower(strings.TrimSpace(k))
		v = strings.TrimSpace(v)

		switch curSection {
		case "interface":
			if k == "privatekey" {
				out.PrivateKey = v
			}
		case "peer":
			if curPeer == nil {
				continue
			}
			switch k {
			case "publickey":
				curPeer.PublicKey = v
			case "endpoint":
				curPeer.Endpoint = v
			case "allowedips":
				parts := strings.Split(v, ",")
				curPeer.AllowedIPs = curPeer.AllowedIPs[:0]
				for _, p := range parts {
					p = strings.TrimSpace(p)
					if p != "" {
						curPeer.AllowedIPs = append(curPeer.AllowedIPs, p)
					}
				}
			}
		}
	}
	if err := s.Err(); err != nil {
		return wgConfig{}, fmt.Errorf("scan wg config: %w", err)
	}
	return out, nil
}

func wgSetConf(ifName, cfgPath string) error {
	if _, err := exec.LookPath("wg"); err != nil {
		return fmt.Errorf("wg tool not found in PATH: %w", err)
	}
	cmd := exec.Command("wg", "setconf", ifName, cfgPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			return fmt.Errorf("wg setconf %s: %w", ifName, err)
		}
		return fmt.Errorf("wg setconf %s: %w: %s", ifName, err, msg)
	}
	return nil
}

// === Main ===

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	debug := os.Getenv("VPN_BRIDGE_DEBUG") != ""

	f := parseFlags()
	if f.socketPath == "" || f.wgConfig == "" || f.vmCIDR == "" || f.gatewayIP == "" {
		flag.Usage()
		os.Exit(2)
	}
	if f.mtu <= 0 {
		log.Fatalf("invalid mtu: %d", f.mtu)
	}

	_, _, err := net.ParseCIDR(f.vmCIDR)
	if err != nil {
		log.Fatalf("parse --vm-ip %q: %v", f.vmCIDR, err)
	}
	gatewayIP := net.ParseIP(f.gatewayIP).To4()
	if gatewayIP == nil {
		log.Fatalf("parse --gateway-ip %q: not an IPv4 address", f.gatewayIP)
	}

	bridgeMAC, err := randomLocalMAC()
	if err != nil {
		log.Fatalf("bridge mac: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	dhcpStubLog()

	uds, err := dialSeqpacket(f.socketPath)
	if err != nil {
		log.Fatalf("uds connect: %v", err)
	}
	defer uds.Close()
	log.Printf("uds connected remote=%s", uds.remote)

	tun, tunName, err := createTUN(f.mtu)
	if err != nil {
		log.Fatalf("tun: %v", err)
	}
	defer tun.Close()
	log.Printf("tun created name=%s mtu=%d", tunName, f.mtu)

	wgc, err := parseWGConfig(f.wgConfig)
	if err != nil {
		log.Fatalf("wg config parse: %v", err)
	}
	if wgc.PrivateKey == "" {
		log.Printf("wg config: missing interface private key")
	}
	if len(wgc.Peers) == 0 {
		log.Printf("wg config: no peers")
	}
	if len(wgc.Peers) > 0 {
		p := wgc.Peers[0]
		log.Printf("wg config: peer endpoint=%s allowed_ips=%d", p.Endpoint, len(p.AllowedIPs))
	}

	if err := wgSetConf(tunName, f.wgConfig); err != nil {
		log.Fatalf("wg setconf: %v", err)
	}
	log.Printf("wg configured on %s via wg setconf", tunName)

	var st bridgeState
	var vmToTunPkts atomic.Uint64
	var vmToTunBytes atomic.Uint64
	var tunToVMPkts atomic.Uint64
	var tunToVMBytes atomic.Uint64
	var droppedNoVMMAC atomic.Uint64

	errCh := make(chan error, 2)

	// VM -> Internet
	go func() {
		buf := make([]byte, 65535)
		for {
			n, err := uds.ReadFrame(buf)
			if err != nil {
				if errors.Is(err, net.ErrClosed) || errors.Is(err, os.ErrClosed) || ctx.Err() != nil {
					errCh <- nil
					return
				}
				errCh <- fmt.Errorf("uds read: %w", err)
				return
			}
			frame := buf[:n]

			_, srcMAC, etherType, payload, err := parseEthernet(frame)
			if err != nil {
				continue
			}
			st.setVMMAC(srcMAC)

			switch etherType {
			case etherTypeIPv4, etherTypeIPv6:
				if len(payload) == 0 {
					continue
				}
				_, err := tun.Write(payload)
				if err != nil {
					errCh <- fmt.Errorf("tun write: %w", err)
					return
				}
				vmToTunPkts.Add(1)
				vmToTunBytes.Add(uint64(len(payload)))
			case etherTypeARP:
				reply, ok := tryARPReply(frame, gatewayIP, bridgeMAC)
				if !ok {
					continue
				}
				if err := uds.WriteFrame(reply); err != nil {
					errCh <- fmt.Errorf("uds write arp: %w", err)
					return
				}
			default:
				continue
			}
		}
	}()

	// Internet -> VM
	go func() {
		buf := make([]byte, 65535)
		for {
			n, err := tun.Read(buf)
			if err != nil {
				if errors.Is(err, net.ErrClosed) || errors.Is(err, os.ErrClosed) || ctx.Err() != nil {
					errCh <- nil
					return
				}
				errCh <- fmt.Errorf("tun read: %w", err)
				return
			}
			pkt := buf[:n]
			et, ok := ipEtherType(pkt)
			if !ok {
				continue
			}

			vmMAC, ok := st.getVMMAC()
			if !ok {
				droppedNoVMMAC.Add(1)
				continue
			}

			frame := wrapEthernet(pkt, vmMAC, bridgeMAC, et)
			if err := uds.WriteFrame(frame); err != nil {
				errCh <- fmt.Errorf("uds write: %w", err)
				return
			}
			tunToVMPkts.Add(1)
			tunToVMBytes.Add(uint64(len(pkt)))
		}
	}()

	if debug {
		go func() {
			t := time.NewTicker(10 * time.Second)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					log.Printf(
						"debug stats: vm->tun pkts=%d bytes=%d tun->vm pkts=%d bytes=%d dropped_no_vm_mac=%d",
						vmToTunPkts.Load(), vmToTunBytes.Load(), tunToVMPkts.Load(), tunToVMBytes.Load(), droppedNoVMMAC.Load(),
					)
				}
			}
		}()
	}

	select {
	case <-ctx.Done():
		log.Printf("signal received; shutting down")
	case err := <-errCh:
		if err != nil {
			log.Printf("error: %v", err)
		}
	}

	stop()
	_ = tun.Close()
	_ = uds.Close()

	// Drain to avoid goroutine leak on clean exit.
	select {
	case <-errCh:
	case <-time.After(250 * time.Millisecond):
	}
	log.Printf(
		"exit stats: vm->tun pkts=%d bytes=%d tun->vm pkts=%d bytes=%d dropped_no_vm_mac=%d",
		vmToTunPkts.Load(), vmToTunBytes.Load(), tunToVMPkts.Load(), tunToVMBytes.Load(), droppedNoVMMAC.Load(),
	)
}
