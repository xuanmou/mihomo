//go:build linux

package tun

func frameOutbound(tun Tun, packet []byte) []byte {
	native, ok := tun.(*NativeTun)
	if !ok || !native.vnetHdr {
		return packet
	}
	framed := make([]byte, virtioNetHdrLen+len(packet))
	copy(framed[virtioNetHdrLen:], packet)
	return framed
}
