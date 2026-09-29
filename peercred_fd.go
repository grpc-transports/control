// SPDX-License-Identifier: BSD-3-Clause

//go:build linux || darwin || freebsd

package control

import (
	"net"
	"syscall"
)

// peerUID asks the kernel who is at the other end of c.
func peerUID(c net.Conn) (uid uint32, ok bool) {
	sc, isSC := c.(syscall.Conn)
	if !isSC {
		return 0, false
	}
	rc, err := sc.SyscallConn()
	if err != nil {
		return 0, false
	}
	if err := rc.Control(func(fd uintptr) { uid, ok = sockUID(int(fd)) }); err != nil {
		return 0, false
	}
	return uid, ok
}
