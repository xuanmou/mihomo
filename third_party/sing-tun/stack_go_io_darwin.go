//go:build darwin

package tun

import (
	"unsafe"

	rawfile "github.com/metacubex/sing-tun/internal/rawfile_darwin"

	"golang.org/x/sys/unix"
)

func receiveMessageBatch(fd int, headers []rawfile.MsgHdrX) (int, unix.Errno) {
	if len(headers) == 0 {
		return 0, 0
	}
	//nolint:staticcheck
	n, _, errno := unix.RawSyscall6(unix.SYS_RECVMSG_X, uintptr(fd), uintptr(unsafe.Pointer(&headers[0])), uintptr(len(headers)), unix.MSG_DONTWAIT, 0, 0)
	return int(n), errno
}

func frameOutbound(tun Tun, packet []byte) []byte {
	family := byte(unix.AF_INET)
	if len(packet) > 0 && packet[0]>>4 == 6 {
		family = byte(unix.AF_INET6)
	}
	framed := make([]byte, PacketOffset+len(packet))
	framed[3] = family
	copy(framed[PacketOffset:], packet)
	return framed
}
