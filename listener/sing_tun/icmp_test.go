package sing_tun

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/component/dialer"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener/sing"

	"github.com/metacubex/sing/common/buf"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
)

func buildICMPv4Echo(source, destination netip.Addr, icmpType byte, ident, sequence uint16, payload []byte) []byte {
	packet := make([]byte, 20+8+len(payload))
	totalLength := len(packet)
	packet[0] = 0x45
	packet[2], packet[3] = byte(totalLength>>8), byte(totalLength)
	packet[8] = 64
	packet[9] = ipProtocolICMPv4
	source4 := source.As4()
	destination4 := destination.As4()
	copy(packet[12:16], source4[:])
	copy(packet[16:20], destination4[:])
	packet[10], packet[11] = 0, 0
	checksumValue := checksum(packet[:20])
	packet[10], packet[11] = byte(checksumValue>>8), byte(checksumValue)

	icmpHeader := packet[20:]
	icmpHeader[0] = icmpType
	icmpHeader[4], icmpHeader[5] = byte(ident>>8), byte(ident)
	icmpHeader[6], icmpHeader[7] = byte(sequence>>8), byte(sequence)
	copy(icmpHeader[8:], payload)
	icmpChecksum := checksum(icmpHeader)
	icmpHeader[2], icmpHeader[3] = byte(icmpChecksum>>8), byte(icmpChecksum)
	return packet
}

func buildICMPv6Echo(source, destination netip.Addr, icmpType byte, ident, sequence uint16, payload []byte) []byte {
	packet := make([]byte, 40+8+len(payload))
	packet[0] = 0x60
	packet[4], packet[5] = byte((8+len(payload))>>8), byte(8+len(payload))
	packet[6] = ipProtocolICMPv6
	packet[7] = 64
	source16 := source.As16()
	destination16 := destination.As16()
	copy(packet[8:24], source16[:])
	copy(packet[24:40], destination16[:])

	icmpHeader := packet[40:]
	icmpHeader[0] = icmpType
	icmpHeader[4], icmpHeader[5] = byte(ident>>8), byte(ident)
	icmpHeader[6], icmpHeader[7] = byte(sequence>>8), byte(sequence)
	copy(icmpHeader[8:], payload)
	checksumValue := icmpv6Checksum(source, destination, icmpHeader)
	icmpHeader[2], icmpHeader[3] = byte(checksumValue>>8), byte(checksumValue)
	return packet
}

// fold16 sums 16-bit words the way a checksum validation does, independently of the
// implementation under test.
func fold16(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return uint16(sum)
}

func icmpv6PseudoHeaderBytes(source, destination netip.Addr, message []byte) []byte {
	source16 := source.As16()
	destination16 := destination.As16()
	length := uint32(len(message))
	pseudo := make([]byte, 0, 40+len(message))
	pseudo = append(pseudo, source16[:]...)
	pseudo = append(pseudo, destination16[:]...)
	pseudo = append(pseudo, byte(length>>24), byte(length>>16), byte(length>>8), byte(length), 0, 0, 0, ipProtocolICMPv6)
	return append(pseudo, message...)
}

func TestParseAndRewriteICMPv4EchoRequest(t *testing.T) {
	source := netip.MustParseAddr("198.18.0.1")
	destination := netip.MustParseAddr("8.8.8.8")
	packet := buildICMPv4Echo(source, destination, icmpv4EchoRequest, 0x1234, 7, []byte("ping"))
	original := append([]byte(nil), packet...)

	if sum := fold16(packet[:20]); sum != 0xffff {
		t.Fatalf("built header checksum = %#x, want 0xffff", sum)
	}
	parsed, ok := parseICMPPacket(packet)
	if !ok {
		t.Fatal("parseICMPPacket rejected a valid echo request")
	}
	if parsed.version != 4 || !parsed.echoRequest || parsed.echoReply {
		t.Fatalf("parsed = %+v", parsed)
	}
	if parsed.source != source || parsed.destination != destination || parsed.ident != 0x1234 || parsed.sequence != 7 {
		t.Fatalf("parsed = %+v", parsed)
	}

	local := netip.MustParseAddr("10.0.0.2")
	if !rewriteICMPPacket(packet, local, netip.Addr{}) {
		t.Fatal("rewriteICMPPacket failed")
	}
	parsed, ok = parseICMPPacket(packet)
	if !ok {
		t.Fatal("parseICMPPacket rejected the rewritten packet")
	}
	if parsed.source != local || parsed.destination != destination {
		t.Fatalf("rewritten addresses = %s -> %s", parsed.source, parsed.destination)
	}
	if sum := fold16(packet[:20]); sum != 0xffff {
		t.Fatalf("rewritten header checksum = %#x, want 0xffff", sum)
	}
	if sum := fold16(packet[20:]); sum != 0xffff {
		t.Fatalf("ICMPv4 checksum changed by an address rewrite: %#x", sum)
	}
	if payload := string(packet[28:]); payload != "ping" {
		t.Fatalf("payload = %q", payload)
	}

	if !rewriteICMPPacket(packet, source, netip.Addr{}) {
		t.Fatal("rewriteICMPPacket failed on the way back")
	}
	if string(packet) != string(original) {
		t.Fatal("rewriting the source address back did not restore the packet")
	}
}

func TestParseAndRewriteICMPv6EchoRequest(t *testing.T) {
	source := netip.MustParseAddr("fdfe:dcba:9876::1")
	destination := netip.MustParseAddr("2001:4860:4860::8888")
	packet := buildICMPv6Echo(source, destination, icmpv6EchoRequest, 0xabcd, 3, []byte("pong"))
	original := append([]byte(nil), packet...)

	if sum := fold16(icmpv6PseudoHeaderBytes(source, destination, packet[40:])); sum != 0xffff {
		t.Fatalf("built ICMPv6 checksum = %#x, want 0xffff", sum)
	}
	parsed, ok := parseICMPPacket(packet)
	if !ok || parsed.version != 6 || !parsed.echoRequest {
		t.Fatalf("parsed = %+v, ok = %v", parsed, ok)
	}

	local := netip.MustParseAddr("2001:db8::2")
	if !rewriteICMPPacket(packet, local, netip.Addr{}) {
		t.Fatal("rewriteICMPPacket failed")
	}
	parsed, ok = parseICMPPacket(packet)
	if !ok || parsed.source != local || parsed.destination != destination {
		t.Fatalf("rewritten packet = %+v, ok = %v", parsed, ok)
	}
	// the ICMPv6 checksum covers the pseudo header, so it must still validate
	if sum := fold16(icmpv6PseudoHeaderBytes(local, destination, packet[40:])); sum != 0xffff {
		t.Fatalf("rewritten ICMPv6 checksum = %#x, want 0xffff", sum)
	}

	if !rewriteICMPPacket(packet, source, netip.Addr{}) {
		t.Fatal("rewriteICMPPacket failed on the way back")
	}
	if string(packet) != string(original) {
		t.Fatal("rewriting the source address back did not restore the packet")
	}
}

func TestRewriteICMPv4EchoReplyDestination(t *testing.T) {
	source := netip.MustParseAddr("10.0.0.2")
	destination := netip.MustParseAddr("8.8.8.8")
	client := netip.MustParseAddr("198.18.0.1")
	packet := buildICMPv4Echo(destination, source, icmpv4EchoReply, 0x1234, 7, []byte("ping"))

	if !rewriteICMPPacket(packet, netip.Addr{}, client) {
		t.Fatal("rewriteICMPPacket failed")
	}
	parsed, ok := parseICMPPacket(packet)
	if !ok || !parsed.echoReply {
		t.Fatalf("parsed = %+v, ok = %v", parsed, ok)
	}
	if parsed.source != destination || parsed.destination != client {
		t.Fatalf("reply addresses = %s -> %s", parsed.source, parsed.destination)
	}
	if sum := fold16(packet[:20]); sum != 0xffff {
		t.Fatalf("reply header checksum = %#x, want 0xffff", sum)
	}
}

func TestParseICMPPacketRejectsOtherPackets(t *testing.T) {
	source := netip.MustParseAddr("198.18.0.1")
	destination := netip.MustParseAddr("8.8.8.8")

	reply := buildICMPv4Echo(source, destination, icmpv4EchoReply, 1, 1, nil)
	if parsed, ok := parseICMPPacket(reply); !ok || parsed.echoRequest || !parsed.echoReply {
		t.Fatalf("echo reply parsed as %+v, ok = %v", parsed, ok)
	}

	udp := buildICMPv4Echo(source, destination, icmpv4EchoRequest, 1, 1, nil)
	udp[9] = 17
	if _, ok := parseICMPPacket(udp); ok {
		t.Fatal("a UDP packet parsed as ICMP")
	}

	if _, ok := parseICMPPacket(nil); ok {
		t.Fatal("an empty packet parsed as ICMP")
	}
	if _, ok := parseICMPPacket([]byte{0x45}); ok {
		t.Fatal("a truncated packet parsed as ICMP")
	}
}

// baseStub carries the extra methods the auto close wrapper of adapter.ParseProxy needs, so the
// stubs below can be wrapped exactly like real outbounds are.
type baseStub struct{}

func (baseStub) DialOptions() []dialer.Option { return nil }

func (baseStub) ResolveUDP(ctx context.Context, metadata *C.Metadata) error { return nil }

type fakeICMPAdapter struct {
	baseStub
	C.ProxyAdapter
	conn net.Conn
}

func (a *fakeICMPAdapter) NewICMPConn(ctx context.Context, metadata *C.Metadata) (net.Conn, error) {
	return a.conn, nil
}

// Unwrap mirrors a real outbound: only proxy groups unwrap to another proxy.
func (a *fakeICMPAdapter) Unwrap(metadata *C.Metadata, touch bool) C.Proxy {
	return nil
}

// plainAdapter is an outbound that cannot carry ICMP, like most proxy protocols.
type plainAdapter struct {
	baseStub
	C.ProxyAdapter
}

func (a *plainAdapter) Type() C.AdapterType { return C.Vmess }

func (a *plainAdapter) Unwrap(metadata *C.Metadata, touch bool) C.Proxy {
	return nil
}

// rejectAdapter is a rule action which rejects the request instead of carrying it.
type rejectAdapter struct {
	baseStub
	C.ProxyAdapter
}

func (a *rejectAdapter) Type() C.AdapterType { return C.Reject }

func (a *rejectAdapter) Unwrap(metadata *C.Metadata, touch bool) C.Proxy {
	return nil
}

// fakeGroupAdapter mirrors a proxy group: it unwraps to the member it selected.
type fakeGroupAdapter struct {
	C.ProxyAdapter
	selected C.Proxy
}

func (g *fakeGroupAdapter) Unwrap(metadata *C.Metadata, touch bool) C.Proxy {
	return g.selected
}

func TestResolveICMPOutboundUnwrapsAdapterWrapper(t *testing.T) {
	inner := &fakeICMPAdapter{}
	// rule matching returns proxies wrapped by adapter.NewProxy, which only promotes the
	// C.ProxyAdapter methods and hides the optional ICMPProxyAdapter interface
	wrapper := adapter.NewProxy(inner)
	resolved := resolveICMPOutbound(wrapper, &C.Metadata{})
	if resolved != C.ProxyAdapter(inner) {
		t.Fatalf("resolveICMPOutbound = %#v, want the outbound behind the wrapper", resolved)
	}
	if _, ok := resolved.(C.ICMPProxyAdapter); !ok {
		t.Fatal("the outbound behind the wrapper does not report ICMP support")
	}

	// a proxy group resolves to the member it selected
	group := adapter.NewProxy(&fakeGroupAdapter{selected: adapter.NewProxy(inner)})
	if resolved = resolveICMPOutbound(group, &C.Metadata{}); resolved != C.ProxyAdapter(inner) {
		t.Fatalf("group resolveICMPOutbound = %#v, want the selected member", resolved)
	}

	// adapter.ParseProxy wraps every outbound in the auto close adapter before adapter.NewProxy,
	// which hides optional interfaces in exactly the same way
	autoClosed := adapter.NewProxy(outbound.NewAutoCloseProxyAdapter(inner))
	if resolved = resolveICMPOutbound(autoClosed, &C.Metadata{}); resolved != C.ProxyAdapter(inner) {
		t.Fatalf("auto closed resolveICMPOutbound = %#v, want the outbound behind the wrapper", resolved)
	}
	if _, ok := resolved.(C.ICMPProxyAdapter); !ok {
		t.Fatal("the outbound behind the auto close wrapper does not report ICMP support")
	}

	// an outbound without ICMP support stays itself and must not report support
	plain := adapter.NewProxy(outbound.NewAutoCloseProxyAdapter(&plainAdapter{}))
	resolved = resolveICMPOutbound(plain, &C.Metadata{})
	if resolved == nil {
		t.Fatal("resolveICMPOutbound lost a plain outbound")
	}
	if _, ok := resolved.(C.ICMPProxyAdapter); ok {
		t.Fatal("a plain outbound reported ICMP support")
	}
}

// TestResolveICMPOutboundUnwrapsNestedWrappers covers outbounds wrapped more than once, which the
// rule engine can hand out when proxies arrive through different construction paths.
func TestResolveICMPOutboundUnwrapsNestedWrappers(t *testing.T) {
	inner := &fakeICMPAdapter{}
	var nested C.ProxyAdapter = adapter.NewProxy(adapter.NewProxy(inner))
	if _, ok := nested.(C.ICMPProxyAdapter); ok {
		t.Fatal("a wrapper must not expose the optional interface on its own")
	}
	outbound := resolveICMPOutbound(nested, &C.Metadata{})
	if outbound != C.ProxyAdapter(inner) {
		t.Fatalf("resolveICMPOutbound = %#v, want the outbound behind both wrappers", outbound)
	}
}

// TestCanHandleICMP covers the decision the rule matcher uses to skip a rule whose outbound cannot
// handle ICMP, the way UDP rules already skip outbounds without UDP support.
func TestCanHandleICMP(t *testing.T) {
	metadata := &C.Metadata{NetWork: C.ICMP}

	if !C.CanHandleICMP(adapter.NewProxy(outbound.NewAutoCloseProxyAdapter(&fakeICMPAdapter{})), metadata) {
		t.Fatal("an ICMP capable outbound behind the wrappers reported no support")
	}
	if C.CanHandleICMP(adapter.NewProxy(outbound.NewAutoCloseProxyAdapter(&plainAdapter{})), metadata) {
		t.Fatal("a plain outbound reported ICMP support")
	}
	if !C.CanHandleICMP(adapter.NewProxy(outbound.NewAutoCloseProxyAdapter(&directAdapter{})), metadata) {
		t.Fatal("a rule which selects a direct route must keep matching")
	}
	if !C.CanHandleICMP(adapter.NewProxy(outbound.NewAutoCloseProxyAdapter(&rejectAdapter{})), metadata) {
		t.Fatal("a rule which rejects the request must keep matching")
	}
	group := adapter.NewProxy(&fakeGroupAdapter{selected: adapter.NewProxy(&fakeICMPAdapter{})})
	if !C.CanHandleICMP(group, metadata) {
		t.Fatal("a group whose selected member carries ICMP reported no support")
	}
	directGroup := adapter.NewProxy(&fakeGroupAdapter{selected: adapter.NewProxy(&directAdapter{})})
	if !C.CanHandleICMP(directGroup, metadata) {
		t.Fatal("a group whose selected member is a direct route reported no support")
	}
	plainGroup := adapter.NewProxy(&fakeGroupAdapter{selected: adapter.NewProxy(&plainAdapter{})})
	if C.CanHandleICMP(plainGroup, metadata) {
		t.Fatal("a group whose selected member cannot carry ICMP reported support")
	}
}

// directAdapter is the built in DIRECT action.
type directAdapter struct {
	baseStub
	C.ProxyAdapter
}

func (a *directAdapter) Type() C.AdapterType { return C.Direct }

func (a *directAdapter) Unwrap(metadata *C.Metadata, touch bool) C.Proxy {
	return nil
}

type localAddrConn struct {
	net.Conn
	local net.Addr
}

func (c *localAddrConn) LocalAddr() net.Addr {
	return c.local
}

type recordedRouteContext struct {
	packets chan []byte
}

func (r *recordedRouteContext) WritePacket(packet []byte) error {
	copied := make([]byte, len(packet))
	copy(copied, packet)
	r.packets <- copied
	return nil
}

func TestICMPProxyDestinationRoundTrip(t *testing.T) {
	source := netip.MustParseAddr("198.18.0.1")
	destination := netip.MustParseAddr("8.8.8.8")
	local := netip.MustParseAddr("10.0.0.2")

	proxySide, clientSide := net.Pipe()
	defer clientSide.Close()
	adapterForTest := &fakeICMPAdapter{conn: &localAddrConn{
		Conn:  proxySide,
		local: net.TCPAddrFromAddrPort(netip.AddrPortFrom(local, 0)),
	}}
	route := &recordedRouteContext{packets: make(chan []byte, 4)}
	d := newICMPProxyDestination(context.Background(), adapterForTest, &C.Metadata{NetWork: C.ICMP, DstIP: destination}, source, route, 5*time.Second, nil)
	defer d.Close()

	request := buildICMPv4Echo(source, destination, icmpv4EchoRequest, 0x22, 1, []byte("ping"))
	buffer := buf.NewSize(len(request))
	if _, err := buffer.Write(request); err != nil {
		t.Fatalf("write buffer: %v", err)
	}
	writeErr := make(chan error, 1)
	go func() { writeErr <- d.WritePacket(buffer) }()

	forwarded := make([]byte, 1024)
	_ = clientSide.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := clientSide.Read(forwarded)
	if err != nil {
		t.Fatalf("read forwarded request: %v", err)
	}
	if err = <-writeErr; err != nil {
		t.Fatalf("WritePacket: %v", err)
	}
	forwardedPacket, ok := parseICMPPacket(forwarded[:n])
	if !ok {
		t.Fatal("the forwarded packet is not a complete ICMP packet")
	}
	if forwardedPacket.source != local {
		t.Fatalf("forwarded source = %s, want the stack address %s", forwardedPacket.source, local)
	}
	if forwardedPacket.destination != destination {
		t.Fatalf("forwarded destination = %s, want %s", forwardedPacket.destination, destination)
	}
	if sum := fold16(forwarded[:20]); sum != 0xffff {
		t.Fatalf("forwarded header checksum = %#x, want 0xffff", sum)
	}

	reply := buildICMPv4Echo(destination, local, icmpv4EchoReply, 0x22, 1, []byte("ping"))
	if _, err = clientSide.Write(reply); err != nil {
		t.Fatalf("write reply: %v", err)
	}
	select {
	case packet := <-route.packets:
		replyPacket, ok := parseICMPPacket(packet)
		if !ok || !replyPacket.echoReply {
			t.Fatalf("written back packet = %+v, ok = %v", replyPacket, ok)
		}
		if replyPacket.source != destination || replyPacket.destination != source {
			t.Fatalf("reply addresses = %s -> %s, want %s -> %s", replyPacket.source, replyPacket.destination, destination, source)
		}
		if sum := fold16(packet[:20]); sum != 0xffff {
			t.Fatalf("reply header checksum = %#x, want 0xffff", sum)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the reply was not written back to the TUN device")
	}
}

// icmpTunnelStub stands in for the tunnel and returns the outbound a rule selected.
type icmpTunnelStub struct {
	C.Tunnel
	adapter C.ProxyAdapter
}

func (t *icmpTunnelStub) HandleICMPRequest(metadata *C.Metadata) (C.ProxyAdapter, C.Rule, error) {
	return t.adapter, nil, nil
}

type routeContextStub struct{}

func (c *routeContextStub) WritePacket(packet []byte) error { return nil }

// TestPrepareICMPProxyUsesMasqueOutbound runs the whole decision with a real masque outbound
// wrapped by adapter.NewProxy, the way the rule engine hands it out.
func TestPrepareICMPProxyUsesMasqueOutbound(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	privateDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}

	masque, err := outbound.NewMasque(outbound.MasqueOption{
		Name:       "warp-masque",
		Server:     "162.159.197.2",
		Port:       443,
		PrivateKey: base64.StdEncoding.EncodeToString(privateDER),
		PublicKey:  base64.StdEncoding.EncodeToString(publicDER),
		Ip:         "100.96.0.12",
		Ipv6:       "2606:4700:cf1:1000::c",
		MTU:        1280,
		UDP:        true,
		IPStack:    outbound.IPStackOption{Mode: "mips"},
	})
	if err != nil {
		t.Fatalf("create masque outbound: %v", err)
	}
	defer func() { _ = masque.Close() }()

	// mirror adapter.ParseProxy: every outbound is wrapped by the auto close adapter before it is
	// wrapped by adapter.NewProxy
	wrapped := outbound.NewAutoCloseProxyAdapter(masque)
	handler := &ListenerHandler{
		ListenerHandler: &sing.ListenerHandler{ListenerConfig: sing.ListenerConfig{
			Tunnel: &icmpTunnelStub{adapter: adapter.NewProxy(wrapped)},
			Type:   C.TUN,
		}},
	}
	source := M.SocksaddrFrom(netip.MustParseAddr("198.18.0.1"), 0)
	destination := M.SocksaddrFrom(netip.MustParseAddr("142.250.198.46"), 0)
	routeDestination, err := handler.PrepareConnection(N.NetworkICMP, source, destination, &routeContextStub{}, 10*time.Second)
	if err != nil {
		t.Fatalf("PrepareConnection: %v", err)
	}
	if routeDestination == nil {
		t.Fatal("PrepareConnection fell back to a direct route instead of using the masque outbound")
	}
	_ = routeDestination.Close()
}
