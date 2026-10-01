// SPDX-License-Identifier: BSD-3-Clause

//go:build linux || darwin || freebsd

package control

import (
	"fmt"
	"net"
	"syscall"
)

// checkServerUID refuses c unless the kernel names its peer and trusted
// accepts that uid. A unix connection whose peer cannot be read here is an
// anomaly, refused rather than waved through.
func checkServerUID(c net.Conn, trusted func(uint32) bool) error {
	uid, ok := peerUID(c)
	if !ok {
		return fmt.Errorf("control: cannot read the uid of the server behind the socket; not sending it anything")
	}
	if !trusted(uid) {
		return fmt.Errorf("control: the server behind the socket runs as uid %d, which is neither ours, root's nor ClientConfig.ServerUID; not sending it anything", uid)
	}
	return nil
}

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
