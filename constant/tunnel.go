package constant

import "net"

type Tunnel interface {
	// HandleTCPConn will handle a tcp connection blocking
	HandleTCPConn(conn net.Conn, metadata *Metadata)
	// HandleUDPPacket will handle a udp packet nonblocking
	HandleUDPPacket(packet UDPPacket, metadata *Metadata)
	// NatTable return nat table
	NatTable() NatTable
	// HandleICMPRequest resolves the outbound selected by the rules for an ICMP echo request.
	// The returned adapter carries the request when it implements ICMPProxyAdapter, and the caller
	// keeps its own behavior otherwise. A nil adapter with a nil error means the request is not
	// handled here, and a rule rejecting the request returns the reject adapter itself.
	HandleICMPRequest(metadata *Metadata) (ProxyAdapter, Rule, error)
}
