package tun

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"time"

	"github.com/metacubex/sing-tun/gtcpip/header"
	mbuf "github.com/metacubex/sing/common/buf"
	mM "github.com/metacubex/sing/common/metadata"
	mN "github.com/metacubex/sing/common/network"
	sbuf "github.com/sagernet/sing/common/buf"
	sM "github.com/sagernet/sing/common/metadata"
	sN "github.com/sagernet/sing/common/network"
)

// goStackHandler is the handler surface of sing-tun's own TCP/IP stack.
// mihomo's TUN handler speaks the metacubex sing interfaces, so requests are
// translated in goMihomoHandler.
type goStackHandler interface {
	JudgeFlow(network uint8, source netip.AddrPort, destination netip.AddrPort, firstPacket []byte) FlowVerdict
	NewDNSPacket(payload []byte, source sM.Socksaddr, destination sM.Socksaddr, writer sN.PacketWriter)
	sN.TCPConnectionHandlerEx
	sN.UDPConnectionHandlerEx
}

type goMihomoHandler struct {
	inner Handler
}

func newGoMihomoHandler(inner Handler) goStackHandler {
	if inner == nil {
		return nil
	}
	return goMihomoHandler{inner: inner}
}

func (h goMihomoHandler) JudgeFlow(uint8, netip.AddrPort, netip.AddrPort, []byte) FlowVerdict {
	// Routing stays in mihomo after the flow is accepted as a socket.
	return FlowVerdict{Action: ActionAccept}
}

func (h goMihomoHandler) NewDNSPacket(payload []byte, source sM.Socksaddr, destination sM.Socksaddr, writer sN.PacketWriter) {
	h.inner.NewPacket(context.Background(), netip.AddrPortFrom(source.Addr, source.Port), cloneMetacubexPacket(payload), socksMetadata(source, destination), func(mN.PacketConn) mN.PacketWriter {
		return goPacketWriter{inner: writer}
	})
}

func (h goMihomoHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source sM.Socksaddr, destination sM.Socksaddr, onClose sN.CloseHandlerFunc) {
	err := h.inner.NewConnection(ctx, conn, socksMetadata(source, destination))
	if onClose != nil {
		onClose(err)
	}
}

func (h goMihomoHandler) NewPacketConnectionEx(ctx context.Context, conn sN.PacketConn, source sM.Socksaddr, destination sM.Socksaddr, onClose sN.CloseHandlerFunc) {
	go func() {
		var closeErr error
		defer func() {
			if onClose != nil {
				onClose(closeErr)
			}
		}()
		for {
			if ctx.Err() != nil {
				closeErr = ctx.Err()
				return
			}
			inbound := sbuf.NewPacket()
			dest, err := conn.ReadPacket(inbound)
			if err != nil {
				inbound.Release()
				closeErr = err
				return
			}
			buffer := cloneMetacubexPacket(inbound.Bytes())
			inbound.Release()
			h.inner.NewPacket(ctx, netip.AddrPortFrom(source.Addr, source.Port), buffer, socksMetadata(source, dest), func(mN.PacketConn) mN.PacketWriter {
				return goPacketWriter{conn: conn}
			})
		}
	}()
}

func socksMetadata(source sM.Socksaddr, destination sM.Socksaddr) mM.Metadata {
	return mM.Metadata{
		Source:      mM.Socksaddr{Addr: source.Addr, Port: source.Port},
		Destination: mM.Socksaddr{Addr: destination.Addr, Port: destination.Port},
	}
}

type goPacketWriter struct {
	inner sN.PacketWriter
	conn  sN.PacketConn
}

func (w goPacketWriter) WritePacket(buffer *mbuf.Buffer, destination mM.Socksaddr) error {
	defer buffer.Release()
	outbound := cloneSagernetPacket(buffer.Bytes(), goPacketHeadroom(w.conn))
	target := sM.Socksaddr{Addr: destination.Addr, Port: destination.Port}
	if w.conn != nil {
		return w.conn.WritePacket(outbound, target)
	}
	return w.inner.WritePacket(outbound, target)
}

// goPacketHeadroom is the space GoPacketConn.transmit needs before the payload.
// ExtendHeader panics when the buffer starts at zero.
func goPacketHeadroom(conn sN.PacketConn) int {
	nat, ok := conn.(*UDPNatConn)
	if !ok || nat == nil || nat.writer == nil {
		return 0
	}
	headroom, ok := nat.writer.(sN.FrontHeadroom)
	if !ok {
		return 0
	}
	return headroom.FrontHeadroom()
}

func cloneMetacubexPacket(payload []byte) *mbuf.Buffer {
	buffer := mbuf.NewSize(len(payload))
	_, _ = buffer.Write(payload)
	return buffer
}

func cloneSagernetPacket(payload []byte, headroom int) *sbuf.Buffer {
	buffer := sbuf.NewSize(headroom + len(payload))
	if headroom > 0 {
		buffer.Resize(headroom, 0)
	}
	_, _ = buffer.Write(payload)
	return buffer
}

type goICMPWriter struct {
	io goPlatformIO
}

func (w *goICMPWriter) WritePacket(packet []byte) error {
	copied := append([]byte(nil), packet...)
	return w.io.writeDatagram(copied, ForwardFrameMeta{})
}

func (e *goEngine) forwardEcho(packet []byte, parsed *forwardPacket) bool {
	if e.stack.legacy == nil || e.stack.icmpNAT == nil || !echoRequest(parsed) {
		return false
	}
	source := parsed.source.Addr()
	destination := parsed.destination.Addr()
	action, err := e.stack.icmpNAT.Lookup(DirectRouteSession{Source: source, Destination: destination}, func(timeout time.Duration) (DirectRouteDestination, error) {
		return e.stack.legacy.PrepareConnection(
			mN.NetworkICMP,
			mM.SocksaddrFrom(source, 0),
			mM.SocksaddrFrom(destination, 0),
			&goICMPWriter{io: e.platformIO},
			timeout,
		)
	})
	if errors.Is(err, ErrDrop) {
		return true
	}
	if errors.Is(err, ErrReset) {
		reply, ok := BuildICMPError(packet, ICMPErrorAddressUnreachable, netip.Addr{}, 0, 0)
		if ok {
			writeErr := e.platformIO.writeDatagram(reply, ForwardFrameMeta{})
			if writeErr != nil && e.stack.logger != nil {
				e.stack.logger.Trace("go: write echo unreachable: ", writeErr)
			}
		}
		return true
	}
	if err != nil || action == nil {
		return false
	}
	owned := cloneMetacubexPacket(packet)
	writeErr := action.WritePacket(owned)
	if writeErr != nil && e.stack.logger != nil {
		e.stack.logger.Trace("go: write echo request: ", writeErr)
	}
	return true
}

func echoRequest(parsed *forwardPacket) bool {
	if parsed == nil || len(parsed.transport) == 0 {
		return false
	}
	switch parsed.protocol {
	case uint8(header.ICMPv4ProtocolNumber):
		return header.ICMPv4(parsed.transport).Type() == header.ICMPv4Echo
	case uint8(header.ICMPv6ProtocolNumber):
		return header.ICMPv6(parsed.transport).Type() == header.ICMPv6EchoRequest
	default:
		return false
	}
}
