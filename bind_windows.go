// SPDX-License-Identifier: BSD-3-Clause

package control

import (
	"errors"
	"fmt"
	"net"
	"syscall"
)

// bindUnix binds an AF_UNIX socket at path. Windows has no file modes to
// narrow: who may connect is decided by the ACL the socket file inherits
// from its directory, so a daemon should put it in a directory only its
// account can open.
func bindUnix(path string) (net.Listener, error) {
	l, err := netListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, fmt.Errorf("control: %w", err)
	}
	l.SetUnlinkOnClose(false)
	fi, err := osLstat(path)
	if err != nil {
		l.Close()
		return nil, fmt.Errorf("control: %w", err)
	}
	return &unixListener{UnixListener: l, path: path, fi: fi}, nil
}

// wsaeconnrefused is WSAECONNREFUSED, what connecting to an AF_UNIX socket
// file nobody listens on returns.
const wsaeconnrefused = syscall.Errno(10061)

func isRefused(err error) bool {
	return errors.Is(err, wsaeconnrefused) || errors.Is(err, syscall.ECONNREFUSED)
}
