// SPDX-License-Identifier: BSD-3-Clause

//go:build !linux && !darwin && !freebsd

package control

import "net"

// peerUID cannot say here: Windows has no uid, and the other BSDs spell the
// question differently from LOCAL_PEERCRED. Caller reports "unix".
func peerUID(net.Conn) (uint32, bool) { return 0, false }

// checkServerUID accepts every server: without peer credentials there is no
// uid to check. Put the socket in a directory only trusted accounts can
// write, so that nobody else can bind it first.
func checkServerUID(net.Conn, func(uint32) bool) error { return nil }
