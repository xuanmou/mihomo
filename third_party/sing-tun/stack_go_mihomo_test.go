package tun

import (
	"bytes"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/metacubex/sing-tun/gtcpip/header"
	"github.com/metacubex/sing/common/buf"
	mM "github.com/metacubex/sing/common/metadata"
	"github.com/sagernet/sing/common/logger"
	sM "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func TestGoEchoPolicy(t *testing.T) {
	source := netip.MustParseAddr("198.18.0.1")
	target := netip.MustParseAddr("8.8.8.8")
	for _, policy := range []string{"drop", "reset", "fallback"} {
		t.Run(policy, func(t *testing.T) {
			output := &recordIO{}
			engine := testEchoEngine(func(DirectRouteContext) (DirectRouteDestination, error) {
				switch policy {
				case "drop":
					return nil, ErrDrop
				case "reset":
					return nil, ErrReset
				default:
					return nil, errors.New("dial failed")
				}
			}, output)
			answerEchoPacket(t, engine, transportPacket(source, target, 1, []byte{8, 0, 0, 0, 0, 1, 0, 1}))
			switch policy {
			case "drop":
				if len(output.packets) != 0 {
					t.Fatalf("drop emitted %x", output.packets[0])
				}
			case "reset":
				reply := onePacket(t, output)
				if reply[20] != uint8(header.ICMPv4DstUnreachable) || reply[21] != uint8(header.ICMPv4HostUnreachable) {
					t.Fatalf("reset reply = %x", reply)
				}
			default:
				reply := onePacket(t, output)
				if reply[20] != uint8(header.ICMPv4EchoReply) || netip.AddrFrom4([4]byte(reply[12:16])) != target || netip.AddrFrom4([4]byte(reply[16:20])) != source {
					t.Fatalf("fallback reply = %x", reply)
				}
			}
		})
	}
}

func TestGoEchoResetIPv6(t *testing.T) {
	output := &recordIO{}
	engine := testEchoEngine(func(DirectRouteContext) (DirectRouteDestination, error) {
		return nil, ErrReset
	}, output)
	source := netip.MustParseAddr("fd00::2")
	target := netip.MustParseAddr("2001:4860:4860::8888")
	answerEchoPacket(t, engine, transportPacket(source, target, 58, []byte{128, 0, 0, 0, 0, 1, 0, 7}))
	reply := onePacket(t, output)
	if reply[40] != uint8(header.ICMPv6DstUnreachable) || reply[41] != uint8(header.ICMPv6AddressUnreachable) {
		t.Fatalf("ipv6 reset reply = %x", reply)
	}
}

func TestGoEchoForwardsLargeRequest(t *testing.T) {
	payload := make([]byte, 20<<10)
	payload[0] = 8
	packet := transportPacket(netip.MustParseAddr("198.18.0.1"), netip.MustParseAddr("8.8.8.8"), 1, payload)
	capture := &captureDestination{}
	output := &recordIO{}
	engine := testEchoEngine(func(DirectRouteContext) (DirectRouteDestination, error) {
		return capture, nil
	}, output)
	answerEchoPacket(t, engine, packet)
	if len(output.packets) != 0 {
		t.Fatalf("local reply emitted beside the forwarded request: %x", output.packets[0])
	}
	if len(capture.packets) != 1 || len(capture.packets[0]) != len(packet) {
		t.Fatalf("forwarded %d bytes, want %d", len(capture.packets[0]), len(packet))
	}
}

func TestGoPacketWriterReservesUDPHeader(t *testing.T) {
	payload := []byte{1, 2, 3, 4}
	for _, ipVersion := range []uint8{4, 6} {
		name := "ipv4"
		if ipVersion == 6 {
			name = "ipv6"
		}
		t.Run(name, func(t *testing.T) {
			output := &recordIO{}
			writer := &GoPacketConn{platformIO: output}
			client := netip.MustParseAddr("198.18.0.1")
			target := netip.MustParseAddr("8.8.8.8")
			headerLength := header.IPv4MinimumSize + header.UDPMinimumSize
			if ipVersion == 6 {
				client = netip.MustParseAddr("fd00::2")
				target = netip.MustParseAddr("2001:4860:4860::8888")
				headerLength = header.IPv6MinimumSize + header.UDPMinimumSize
			}
			writer.buildTemplate(ipVersion, sM.SocksaddrFrom(client, 1234))
			nat := &UDPNatConn{
				service:  &UDPNat{},
				writer:   writer,
				doneChan: make(chan struct{}),
			}
			packet := buf.NewSize(len(payload))
			_, _ = packet.Write(payload)
			err := (goPacketWriter{conn: nat}).WritePacket(packet, mM.SocksaddrFrom(target, 53))
			if err != nil {
				t.Fatal(err)
			}
			got := onePacket(t, output)
			if len(got) != headerLength+len(payload) || !bytes.Equal(got[headerLength:], payload) {
				t.Fatalf("packet = %x", got)
			}
		})
	}
}

func testEchoEngine(prepare func(DirectRouteContext) (DirectRouteDestination, error), output goPlatformIO) *goEngine {
	handler := &testHandler{prepare: prepare}
	return &goEngine{platformIO: output, stack: &Go{
		legacy:  handler,
		icmpNAT: NewDirectRouteMapping(time.Second),
		logger:  logger.NOP(),
	}}
}

func answerEchoPacket(t *testing.T, engine *goEngine, packet []byte) {
	t.Helper()
	parsed, ok := parseForwardPacket(packet)
	if !ok {
		t.Fatal("parse echo")
	}
	engine.answerEcho(packet, &parsed)
}

func onePacket(t *testing.T, output *recordIO) []byte {
	t.Helper()
	if len(output.packets) != 1 {
		t.Fatalf("got %d replies", len(output.packets))
	}
	return output.packets[0]
}

type captureDestination struct {
	packets [][]byte
}

func (d *captureDestination) WritePacket(buffer *buf.Buffer) error {
	defer buffer.Release()
	d.packets = append(d.packets, append([]byte(nil), buffer.Bytes()...))
	return nil
}

func (d *captureDestination) Close() error { return nil }

func (d *captureDestination) IsClosed() bool { return false }

type recordIO struct {
	packets [][]byte
}

func (r *recordIO) writeDatagram(packet []byte, _ ForwardFrameMeta) error {
	r.packets = append(r.packets, append([]byte(nil), packet...))
	return nil
}

func (r *recordIO) start() error { return nil }
func (r *recordIO) wait(time.Duration, []goSocketEvent) (bool, int, error) {
	return false, 0, nil
}
func (r *recordIO) registerSocket(*goSocket, uint32, uint8) error { return nil }
func (r *recordIO) updateSocket(*goSocket, uint8) error           { return nil }
func (r *recordIO) unregisterSocket(*goSocket)                    {}
func (r *recordIO) readBurst([]goFrame, N.ReadWaitOptions) (int, bool, error) {
	return 0, true, nil
}
func (r *recordIO) writeFrame([][]byte, ForwardFrameMeta) error { return nil }
func (r *recordIO) writePacket(packet []byte, meta ForwardFrameMeta) error {
	return r.writeDatagram(packet, meta)
}
func (r *recordIO) writeData([][]byte, ForwardFrameMeta, *GoConn, uint64) error { return nil }
func (r *recordIO) writePacketBatch([]goUDPFrame) error                         { return nil }
func (r *recordIO) transmitBacklogBelowBatch(*GoConn) bool                      { return true }
func (r *recordIO) releaseReadBuffers()                                         {}
func (r *recordIO) flush()                                                      {}
func (r *recordIO) mtu() int                                                    { return 1500 }
func (r *recordIO) supportsSockets() bool                                       { return false }
func (r *recordIO) transmitPrefix() int                                         { return 0 }
func (r *recordIO) transmitChecksumOffload() bool                               { return false }
func (r *recordIO) transmitSegmentOffload() bool                                { return false }
func (r *recordIO) armTransmitWritable(*GoConn) (*goBlockedWriters, error) {
	return nil, nil
}
func (r *recordIO) takeTransmitWritable(writable []*goBlockedWriters) []*goBlockedWriters {
	return writable
}
func (r *recordIO) wake()        {}
func (r *recordIO) close() error { return nil }
