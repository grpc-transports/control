// SPDX-License-Identifier: BSD-3-Clause

//go:build unix

package control

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

// bindUnix binds a socket at path that no other user can reach at any
// instant.
//
// bind(2) creates the socket file with mode 0777 &^ umask, and the usual
// umask (022) leaves it connectable by everyone until a chmod follows. The
// umask cannot be narrowed around the bind either: it belongs to the
// process, not the goroutine, so every file other goroutines created in
// that window would silently get the narrower mode.
//
// Instead the socket is bound inside a fresh directory made with mode 0700
// (os.MkdirTemp), so whatever mode bind gave it, only this user can reach
// it; it is chmod'ed to 0600 there; and only then hard-linked to path.
// link(2) refuses to replace an existing file, so a daemon that bound path
// in the meantime is not displaced either. The temporary name and directory
// are then removed; the socket lives on under path.
//
// The directory sits next to path, in the same filesystem, so the link
// cannot cross devices. Its name lengthens the path bound by up to 13
// bytes, which the platform's socket path limit (sun_path: 104 bytes on
// darwin and the BSDs, 108 on Linux) must also accommodate.
func bindUnix(path string) (net.Listener, error) {
	// A longer path could be linked into place, but no client could
	// connect(2) to it.
	if err := fitsSunPath(path, ""); err != nil {
		return nil, err
	}
	tmp, err := os.MkdirTemp(filepath.Dir(path), ".c")
	if err != nil {
		return nil, fmt.Errorf("control: %w", err)
	}
	defer os.RemoveAll(tmp)
	tmpSock := filepath.Join(tmp, "s")
	if err := fitsSunPath(tmpSock, fmt.Sprintf(" while binding it as %s", tmpSock)); err != nil {
		return nil, err
	}

	l, err := netListenUnix("unix", &net.UnixAddr{Name: tmpSock, Net: "unix"})
	if err != nil {
		return nil, fmt.Errorf("control: %w", err)
	}
	// The name net recorded is the temporary one; Close is handled by
	// unixListener, under the real name.
	l.SetUnlinkOnClose(false)

	fi, err := publish(tmpSock, path)
	if err != nil {
		l.Close()
		return nil, err
	}
	return &unixListener{UnixListener: l, path: path, fi: fi}, nil
}

func publish(tmpSock, path string) (os.FileInfo, error) {
	if err := osChmod(tmpSock, 0o600); err != nil {
		return nil, fmt.Errorf("control: %w", err)
	}
	if err := osLink(tmpSock, path); err != nil {
		if errors.Is(err, os.ErrExist) {
			return nil, fmt.Errorf("control: %s appeared while binding; not replacing it", path)
		}
		return nil, fmt.Errorf("control: %w", err)
	}
	fi, err := osLstat(path)
	if err != nil {
		os.Remove(path)
		return nil, fmt.Errorf("control: %w", err)
	}
	return fi, nil
}

// sunPathMax is the longest socket path connect(2) accepts here, keeping
// room for the terminating NUL some kernels require.
const sunPathMax = len(unix.RawSockaddrUnix{}.Path) - 1

func fitsSunPath(path, while string) error {
	if len(path) > sunPathMax {
		return fmt.Errorf("control: socket path %s is %d bytes%s; at most %d fit in a unix socket address here",
			path, len(path), while, sunPathMax)
	}
	return nil
}

func isRefused(err error) bool { return errors.Is(err, syscall.ECONNREFUSED) }
