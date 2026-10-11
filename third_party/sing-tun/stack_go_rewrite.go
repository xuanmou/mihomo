package tun

import (
	"net/netip"

	"github.com/metacubex/sing-tun/gtcpip"
	"github.com/metacubex/sing-tun/gtcpip/header"
)

func goRewriteIPv4TCP(ipHdr header.IPv4, tcpHdr header.TCP, txChecksumOffload bool,
	newSource netip.Addr, newSourcePort uint16, rewriteSourcePort bool,
	newDestination netip.Addr, newDestinationPort uint16, rewriteDestinationPort bool,
) {
	oldSource := ipHdr.SourceAddress()
	oldDestination := ipHdr.DestinationAddress()
	newSourceAddr := tcpip.AddrFrom4(newSource.As4())
	newDestinationAddr := tcpip.AddrFrom4(newDestination.As4())
	if newSourceAddr != oldSource {
		ipHdr.SetSourceAddressWithChecksumUpdate(newSourceAddr)
		if !txChecksumOffload {
			tcpHdr.UpdateChecksumPseudoHeaderAddress(oldSource, newSourceAddr, true)
		}
	}
	if newDestinationAddr != oldDestination {
		ipHdr.SetDestinationAddressWithChecksumUpdate(newDestinationAddr)
		if !txChecksumOffload {
			tcpHdr.UpdateChecksumPseudoHeaderAddress(oldDestination, newDestinationAddr, true)
		}
	}
	if txChecksumOffload {
		if rewriteSourcePort {
			tcpHdr.SetSourcePort(newSourcePort)
		}
		if rewriteDestinationPort {
			tcpHdr.SetDestinationPort(newDestinationPort)
		}
		tcpHdr.SetChecksum(0)
		return
	}
	if rewriteSourcePort {
		tcpHdr.SetSourcePortWithChecksumUpdate(newSourcePort)
	}
	if rewriteDestinationPort {
		tcpHdr.SetDestinationPortWithChecksumUpdate(newDestinationPort)
	}
}

func goRewriteIPv6TCP(ipHdr header.IPv6, tcpHdr header.TCP, txChecksumOffload bool,
	newSource netip.Addr, newSourcePort uint16, rewriteSourcePort bool,
	newDestination netip.Addr, newDestinationPort uint16, rewriteDestinationPort bool,
) {
	oldSource := ipHdr.SourceAddress()
	oldDestination := ipHdr.DestinationAddress()
	newSourceAddr := tcpip.AddrFrom16(newSource.As16())
	newDestinationAddr := tcpip.AddrFrom16(newDestination.As16())
	if newSourceAddr != oldSource {
		ipHdr.SetSourceAddress(newSourceAddr)
		if !txChecksumOffload {
			tcpHdr.UpdateChecksumPseudoHeaderAddress(oldSource, newSourceAddr, true)
		}
	}
	if newDestinationAddr != oldDestination {
		ipHdr.SetDestinationAddress(newDestinationAddr)
		if !txChecksumOffload {
			tcpHdr.UpdateChecksumPseudoHeaderAddress(oldDestination, newDestinationAddr, true)
		}
	}
	if txChecksumOffload {
		if rewriteSourcePort {
			tcpHdr.SetSourcePort(newSourcePort)
		}
		if rewriteDestinationPort {
			tcpHdr.SetDestinationPort(newDestinationPort)
		}
		tcpHdr.SetChecksum(0)
		return
	}
	if rewriteSourcePort {
		tcpHdr.SetSourcePortWithChecksumUpdate(newSourcePort)
	}
	if rewriteDestinationPort {
		tcpHdr.SetDestinationPortWithChecksumUpdate(newDestinationPort)
	}
}

func rewriteEchoReplyIPv4(ipHdr header.IPv4, icmpHdr header.ICMPv4) bool {
	if icmpHdr.Type() != header.ICMPv4Echo || icmpHdr.Code() != 0 {
		return false
	}
	icmpHdr.SetType(header.ICMPv4EchoReply)
	sourceAddress := ipHdr.SourceAddr()
	ipHdr.SetSourceAddr(ipHdr.DestinationAddr())
	ipHdr.SetDestinationAddr(sourceAddress)
	icmpHdr.SetChecksum(header.ICMPv4Checksum(icmpHdr, 0))
	ipHdr.SetChecksum(^ipHdr.CalculateChecksum())
	return true
}

func rewriteEchoReplyIPv6(ipHdr header.IPv6, icmpHdr header.ICMPv6) bool {
	if icmpHdr.Type() != header.ICMPv6EchoRequest || icmpHdr.Code() != 0 {
		return false
	}
	icmpHdr.SetType(header.ICMPv6EchoReply)
	sourceAddress := ipHdr.SourceAddr()
	ipHdr.SetSourceAddr(ipHdr.DestinationAddr())
	ipHdr.SetDestinationAddr(sourceAddress)
	icmpHdr.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
		Header: icmpHdr,
		Src:    ipHdr.SourceAddressSlice(),
		Dst:    ipHdr.DestinationAddressSlice(),
	}))
	return true
}
