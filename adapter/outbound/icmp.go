package outbound

import (
	"context"
	"net"
	"net/netip"

	C "github.com/metacubex/mihomo/constant"

	E "github.com/metacubex/sing/common/exceptions"
)

// dialICMPThroughStack dials an ICMP socket inside an outbound IP stack. The returned connection
// exchanges complete IP packets, including their IP headers, with the network behind the proxy.
func dialICMPThroughStack(ctx context.Context, stack ipStack, destination netip.Addr) (net.Conn, error) {
	if !destination.IsValid() {
		return nil, E.New("invalid ICMP destination")
	}
	network := "ip4:icmp"
	if destination.Is6() {
		network = "ip6:ipv6-icmp"
	}
	return stack.DialIP(ctx, network, netip.Addr{}, destination)
}

var _ C.ICMPProxyAdapter = (*WireGuard)(nil)
var _ C.ICMPProxyAdapter = (*Masque)(nil)
var _ C.ICMPProxyAdapter = (*OpenVPN)(nil)
var _ C.ICMPProxyAdapter = (*ZeroTier)(nil)
