package sing_tun

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/adapter/inbound"
	"github.com/metacubex/mihomo/common/pool"
	"github.com/metacubex/mihomo/component/dialer"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"

	tun "github.com/metacubex/sing-tun"
	"github.com/metacubex/sing-tun/ping"
	"github.com/metacubex/sing/common/buf"
	E "github.com/metacubex/sing/common/exceptions"
	M "github.com/metacubex/sing/common/metadata"
)

const (
	ipProtocolICMPv4 = 1
	ipProtocolICMPv6 = 58

	icmpv4EchoRequest = 8
	icmpv4EchoReply   = 0
	icmpv6EchoRequest = 128
	icmpv6EchoReply   = 129

	maxICMPPacketSize = 65535
)

// icmpPacket is the parsed header of a complete IPv4 or IPv6 ICMP packet.
type icmpPacket struct {
	version     int
	source      netip.Addr
	destination netip.Addr
	ident       uint16
	sequence    uint16
	echoRequest bool
	echoReply   bool
}

// parseICMPPacket parses a complete IP packet carrying ICMP. IPv6 extension headers are not
// followed, because echo requests and replies never carry them.
func parseICMPPacket(packet []byte) (icmpPacket, bool) {
	if len(packet) < 1 {
		return icmpPacket{}, false
	}
	switch packet[0] >> 4 {
	case 4:
		if len(packet) < 20 {
			return icmpPacket{}, false
		}
		headerLength := int(packet[0]&0x0f) * 4
		if headerLength < 20 || len(packet) < headerLength+8 {
			return icmpPacket{}, false
		}
		if packet[9] != ipProtocolICMPv4 {
			return icmpPacket{}, false
		}
		source, sourceOk := netip.AddrFromSlice(packet[12:16])
		destination, destinationOk := netip.AddrFromSlice(packet[16:20])
		if !sourceOk || !destinationOk {
			return icmpPacket{}, false
		}
		icmpHeader := packet[headerLength:]
		return icmpPacket{
			version:     4,
			source:      source.Unmap(),
			destination: destination.Unmap(),
			ident:       binary.BigEndian.Uint16(icmpHeader[4:6]),
			sequence:    binary.BigEndian.Uint16(icmpHeader[6:8]),
			echoRequest: icmpHeader[0] == icmpv4EchoRequest && icmpHeader[1] == 0,
			echoReply:   icmpHeader[0] == icmpv4EchoReply && icmpHeader[1] == 0,
		}, true
	case 6:
		if len(packet) < 40+8 {
			return icmpPacket{}, false
		}
		if packet[6] != ipProtocolICMPv6 {
			return icmpPacket{}, false
		}
		source, sourceOk := netip.AddrFromSlice(packet[8:24])
		destination, destinationOk := netip.AddrFromSlice(packet[24:40])
		if !sourceOk || !destinationOk {
			return icmpPacket{}, false
		}
		icmpHeader := packet[40:]
		return icmpPacket{
			version:     6,
			source:      source.Unmap(),
			destination: destination.Unmap(),
			ident:       binary.BigEndian.Uint16(icmpHeader[4:6]),
			sequence:    binary.BigEndian.Uint16(icmpHeader[6:8]),
			echoRequest: icmpHeader[0] == icmpv6EchoRequest && icmpHeader[1] == 0,
			echoReply:   icmpHeader[0] == icmpv6EchoReply && icmpHeader[1] == 0,
		}, true
	}
	return icmpPacket{}, false
}

// rewriteICMPPacket rewrites the addresses of a complete ICMP packet in place and repairs the
// checksums it invalidates. An invalid address leaves that address unchanged, and a false result
// means the packet was not rewritten.
func rewriteICMPPacket(packet []byte, source, destination netip.Addr) bool {
	if len(packet) < 1 {
		return false
	}
	switch packet[0] >> 4 {
	case 4:
		if len(packet) < 20 {
			return false
		}
		headerLength := int(packet[0]&0x0f) * 4
		if headerLength < 20 || len(packet) < headerLength {
			return false
		}
		if source.IsValid() {
			if !source.Is4() {
				return false
			}
			source4 := source.As4()
			copy(packet[12:16], source4[:])
		}
		if destination.IsValid() {
			if !destination.Is4() {
				return false
			}
			destination4 := destination.As4()
			copy(packet[16:20], destination4[:])
		}
		// the ICMPv4 checksum covers the ICMP message only, so only the IP header checksum changes
		packet[10], packet[11] = 0, 0
		binary.BigEndian.PutUint16(packet[10:12], checksum(packet[:headerLength]))
		return true
	case 6:
		if len(packet) < 40 {
			return false
		}
		if source.IsValid() {
			if !source.Is6() {
				return false
			}
			source16 := source.As16()
			copy(packet[8:24], source16[:])
		}
		if destination.IsValid() {
			if !destination.Is6() {
				return false
			}
			destination16 := destination.As16()
			copy(packet[24:40], destination16[:])
		}
		if packet[6] != ipProtocolICMPv6 {
			return true
		}
		// the ICMPv6 checksum covers the pseudo header, which holds both addresses
		message := packet[40:]
		if len(message) < 4 {
			return false
		}
		currentSource, sourceOk := netip.AddrFromSlice(packet[8:24])
		currentDestination, destinationOk := netip.AddrFromSlice(packet[24:40])
		if !sourceOk || !destinationOk {
			return false
		}
		message[2], message[3] = 0, 0
		binary.BigEndian.PutUint16(message[2:4], icmpv6Checksum(currentSource, currentDestination, message))
		return true
	}
	return false
}

// checksum returns the one's complement checksum of b, as defined by RFC 1071.
func checksum(b []byte) uint16 {
	return ^foldSum(sum16(0, b))
}

func sum16(sum uint32, b []byte) uint32 {
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	return sum
}

func foldSum(sum uint32) uint16 {
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return uint16(sum)
}

// icmpv6Checksum returns the checksum of an ICMPv6 message, including its IPv6 pseudo header.
func icmpv6Checksum(source, destination netip.Addr, message []byte) uint16 {
	source16 := source.As16()
	destination16 := destination.As16()
	length := uint32(len(message))
	sum := sum16(0, source16[:])
	sum = sum16(sum, destination16[:])
	sum = sum16(sum, []byte{
		byte(length >> 24), byte(length >> 16), byte(length >> 8), byte(length),
		0, 0, 0, ipProtocolICMPv6,
	})
	sum = sum16(sum, message)
	return ^foldSum(sum)
}

// prepareICMPProxy returns the destination that sends the echo requests through the outbound
// selected by the rules. A nil destination with a nil error keeps the direct route behavior, while
// ErrReset and ErrDrop tell the stack that the rules rejected the requests.
func (h *ListenerHandler) prepareICMPProxy(source M.Socksaddr, destination M.Socksaddr, routeContext tun.DirectRouteContext, timeout time.Duration) (tun.DirectRouteDestination, error) {
	if h.Tunnel == nil {
		return nil, nil
	}
	metadata := h.icmpMetadata(source, destination)
	adapter, rule, err := h.Tunnel.HandleICMPRequest(metadata)
	if err != nil {
		log.Warnln("[ICMP] %s --> %s match rule error: %s", source, destination, err)
		return nil, nil
	}
	if adapter == nil {
		return nil, nil
	}
	outbound := resolveICMPOutbound(adapter, metadata)
	if outbound == nil {
		outbound = adapter
	}
	switch outbound.Type() {
	case C.Direct, C.Compatible: // no proxy involved: keep the direct route below
		return nil, nil
	case C.Reject, C.RejectDrop:
		log.Infoln("[ICMP] %s --> %s match %s using %s", source, destination, ruleString(rule), outbound.Name())
		if outbound.Type() == C.RejectDrop {
			return nil, tun.ErrDrop
		}
		return nil, tun.ErrReset
	}
	icmpAdapter, ok := outbound.(C.ICMPProxyAdapter)
	if !ok {
		selected := ""
		if outbound.Name() != adapter.Name() {
			selected = ", selected " + outbound.Name()
		}
		log.Infoln("[ICMP] %s --> %s match %s using %s%s cannot carry ICMP (matched %T, resolved %T)", source, destination, ruleString(rule), adapter.Name(), selected, adapter, outbound)
		return nil, nil
	}
	if outbound.Name() != adapter.Name() {
		log.Infoln("[ICMP] %s --> %s match %s using %s, selected %s", source, destination, ruleString(rule), adapter.Name(), outbound.Name())
	} else {
		log.Infoln("[ICMP] %s --> %s match %s using %s", source, destination, ruleString(rule), adapter.Name())
	}
	return newICMPProxyDestination(context.TODO(), icmpAdapter, metadata, source.Addr, routeContext, timeout, func() (tun.DirectRouteDestination, error) {
		return ping.ConnectDestination(context.TODO(), log.SingLogger, dialer.ICMPControl(destination.Addr), destination.Addr, routeContext, timeout)
	}), nil
}

// resolveICMPOutbound returns the real outbound the rules would dial for adapter.
func resolveICMPOutbound(adapter C.ProxyAdapter, metadata *C.Metadata) C.ProxyAdapter {
	return C.ResolveProxyAdapter(adapter, metadata)
}

func ruleString(rule C.Rule) string {
	if rule == nil {
		return "the tunnel mode"
	}
	return fmt.Sprintf("%s(%s)", rule.RuleType().String(), rule.Payload())
}

func (h *ListenerHandler) icmpMetadata(source, destination M.Socksaddr) *C.Metadata {
	metadata := &C.Metadata{
		NetWork: C.ICMP,
		Type:    h.Type,
	}
	inbound.ApplyAdditions(metadata, inbound.WithDstAddr(destination), inbound.WithSrcAddr(source))
	inbound.ApplyAdditions(metadata, h.Additions...)
	return metadata
}

// icmpProxyDestination writes the ICMP echo requests received from the TUN device to the outbound
// selected by the rules and writes the replies it returns back to the TUN device. Requests are sent
// by a direct route whenever the outbound cannot carry them.
type icmpProxyDestination struct {
	ctx           context.Context
	adapter       C.ICMPProxyAdapter
	metadata      *C.Metadata
	source        netip.Addr
	destination   netip.Addr
	routeContext  tun.DirectRouteContext
	timeout       time.Duration
	directConnect func() (tun.DirectRouteDestination, error)

	dialAccess sync.Mutex

	access     sync.Mutex
	conn       net.Conn
	localAddr  netip.Addr
	direct     tun.DirectRouteDestination
	dialErr    error
	closed     bool
	lastActive atomic.Int64
}

func newICMPProxyDestination(ctx context.Context, adapter C.ICMPProxyAdapter, metadata *C.Metadata, source netip.Addr, routeContext tun.DirectRouteContext, timeout time.Duration, directConnect func() (tun.DirectRouteDestination, error)) *icmpProxyDestination {
	d := &icmpProxyDestination{
		ctx:           ctx,
		adapter:       adapter,
		metadata:      metadata,
		source:        source.Unmap(),
		destination:   metadata.DstIP,
		routeContext:  routeContext,
		timeout:       timeout,
		directConnect: directConnect,
	}
	d.lastActive.Store(time.Now().UnixNano())
	return d
}

// WritePacket implements tun.DirectRouteDestination, and it takes ownership of packet.
func (d *icmpProxyDestination) WritePacket(packet *buf.Buffer) error {
	defer packet.Release()
	data := packet.Bytes()
	request, ok := parseICMPPacket(data)
	if !ok || !request.echoRequest {
		return E.New("invalid ICMP echo request packet")
	}
	d.lastActive.Store(time.Now().UnixNano())

	conn, err := d.connect()
	if err != nil {
		return d.writeDirect(data, err)
	}
	rewritten := false
	if localAddr := d.localAddress(); localAddr.IsValid() && localAddr != request.source {
		if !rewriteICMPPacket(data, localAddr, netip.Addr{}) {
			return E.New("rewrite ICMP echo request source address")
		}
		rewritten = true
	}
	if _, err = conn.Write(data); err != nil {
		if rewritten { // the direct route sends the request as it was received
			rewriteICMPPacket(data, request.source, netip.Addr{})
		}
		return d.writeDirect(data, err)
	}
	return nil
}

func (d *icmpProxyDestination) Close() error {
	d.access.Lock()
	if d.closed {
		d.access.Unlock()
		return nil
	}
	d.closed = true
	conn := d.conn
	d.conn = nil
	direct := d.direct
	d.direct = nil
	d.access.Unlock()
	if direct != nil {
		_ = direct.Close()
	}
	if conn != nil {
		return conn.Close()
	}
	return nil
}

func (d *icmpProxyDestination) IsClosed() bool {
	d.access.Lock()
	defer d.access.Unlock()
	return d.closed
}

func (d *icmpProxyDestination) connect() (net.Conn, error) {
	if conn := d.currentConn(); conn != nil {
		return conn, nil
	}
	d.dialAccess.Lock()
	defer d.dialAccess.Unlock()
	if conn := d.currentConn(); conn != nil {
		return conn, nil
	}
	if d.IsClosed() {
		return nil, net.ErrClosed
	}
	if d.dialErr != nil { // keep the result until the TUN session is renewed
		return nil, d.dialErr
	}
	ctx, cancel := context.WithTimeout(d.ctx, d.timeout)
	defer cancel()
	conn, err := d.adapter.NewICMPConn(ctx, d.metadata)
	if err != nil {
		log.Warnln("[ICMP] %s --> %s connect %s error: %s", d.source, d.destination, d.adapter.Name(), err)
		d.dialErr = err
		return nil, err
	}
	d.access.Lock()
	if d.closed {
		d.access.Unlock()
		_ = conn.Close()
		return nil, net.ErrClosed
	}
	d.localAddr = localAddrOf(conn)
	d.conn = conn
	d.access.Unlock()
	go d.loopRead(conn)
	return conn, nil
}

func (d *icmpProxyDestination) currentConn() net.Conn {
	d.access.Lock()
	defer d.access.Unlock()
	return d.conn
}

func (d *icmpProxyDestination) localAddress() netip.Addr {
	d.access.Lock()
	defer d.access.Unlock()
	return d.localAddr
}

func (d *icmpProxyDestination) directDestination() (tun.DirectRouteDestination, error) {
	d.access.Lock()
	defer d.access.Unlock()
	if d.direct != nil {
		return d.direct, nil
	}
	if d.closed {
		return nil, net.ErrClosed
	}
	direct, err := d.directConnect()
	if err != nil {
		return nil, err
	}
	d.direct = direct
	return direct, nil
}

func (d *icmpProxyDestination) writeDirect(packet []byte, cause error) error {
	log.Debugln("[ICMP] %s --> %s fallback to DIRECT: %s", d.source, d.destination, cause)
	direct, err := d.directDestination()
	if err != nil {
		return err
	}
	buffer := buf.NewSize(len(packet))
	if _, err = buffer.Write(packet); err != nil {
		buffer.Release()
		return err
	}
	return direct.WritePacket(buffer) // WritePacket takes ownership of the buffer
}

func (d *icmpProxyDestination) loopRead(conn net.Conn) {
	defer func() { _ = d.Close() }()
	for {
		deadline := time.Unix(0, d.lastActive.Load()).Add(d.timeout)
		if !time.Now().Before(deadline) {
			return
		}
		if err := conn.SetReadDeadline(deadline); err != nil {
			return
		}
		buffer := pool.Get(maxICMPPacketSize)
		n, err := conn.Read(buffer)
		if err != nil {
			pool.Put(buffer)
			if E.IsTimeout(err) {
				continue
			}
			if !E.IsClosed(err) {
				log.Warnln("[ICMP] %s --> %s read reply error: %s", d.source, d.destination, err)
			}
			return
		}
		packet := buffer[:n]
		reply, ok := parseICMPPacket(packet)
		if !ok {
			pool.Put(buffer)
			continue
		}
		if reply.destination != d.source {
			if !rewriteICMPPacket(packet, netip.Addr{}, d.source) {
				pool.Put(buffer)
				continue
			}
		}
		d.lastActive.Store(time.Now().UnixNano())
		if err = d.routeContext.WritePacket(packet); err != nil {
			log.Warnln("[ICMP] %s --> %s write reply error: %s", d.source, d.destination, err)
		}
		pool.Put(buffer)
	}
}

// localAddrOf returns the address an outbound IP stack bound an ICMP socket to.
func localAddrOf(conn net.Conn) netip.Addr {
	addr := conn.LocalAddr()
	if addr == nil {
		return netip.Addr{}
	}
	if addrPort, ok := addr.(interface{ AddrPort() netip.AddrPort }); ok {
		if addrPort := addrPort.AddrPort(); addrPort.IsValid() {
			return addrPort.Addr().Unmap()
		}
	}
	if host, _, err := net.SplitHostPort(addr.String()); err == nil {
		if ip, err := netip.ParseAddr(host); err == nil {
			return ip.Unmap()
		}
	}
	if ip, err := netip.ParseAddr(addr.String()); err == nil {
		return ip.Unmap()
	}
	return netip.Addr{}
}
