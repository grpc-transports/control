// SPDX-License-Identifier: BSD-3-Clause

//go:build !linux && !darwin && !freebsd

package control

import "net"

// peerUID cannot say here: Windows has no uid, and the other BSDs spell the
// question differently from LOCAL_PEERCRED. Caller reports "unix".
func peerUID(net.Conn) (uint32, bool) { return 0, false }
