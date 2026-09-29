// SPDX-License-Identifier: BSD-3-Clause

//go:build darwin || freebsd

package control

import "golang.org/x/sys/unix"

// sockUID reads the peer's uid with LOCAL_PEERCRED (what getpeereid(3) is
// built on): the credentials the kernel recorded when the peer connected,
// which the peer cannot forge.
func sockUID(fd int) (uint32, bool) {
	cred, err := unix.GetsockoptXucred(fd, unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	if err != nil {
		return 0, false
	}
	return cred.Uid, true
}
