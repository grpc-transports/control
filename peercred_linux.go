// SPDX-License-Identifier: BSD-3-Clause

package control

import "golang.org/x/sys/unix"

// sockUID reads the peer's uid with SO_PEERCRED: the credentials the kernel
// recorded when the peer connected, which the peer cannot forge.
func sockUID(fd int) (uint32, bool) {
	cred, err := unix.GetsockoptUcred(fd, unix.SOL_SOCKET, unix.SO_PEERCRED)
	if err != nil {
		return 0, false
	}
	return cred.Uid, true
}
