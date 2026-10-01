// SPDX-License-Identifier: BSD-3-Clause

package control

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"google.golang.org/grpc/credentials"
)

// staleDialTimeout bounds the probe that decides whether a socket file left
// at the path still has a daemon behind it.
const staleDialTimeout = 2 * time.Second

// Seams for the filesystem calls whose failure no test can provoke on
// demand; tests swap them to drive the error branches.
var (
	osLstat = os.Lstat
	osChmod = os.Chmod
	osLink  = os.Link

	netListenUnix = net.ListenUnix
)

func listenUnix(path string) (net.Listener, error) {
	if err := clearStale(path); err != nil {
		return nil, err
	}
	return bindUnix(path)
}

// clearStale makes room at path for a new socket, or says why it will not.
// Only a socket that refuses connections is removed: a daemon's live socket
// is never stolen, a socket we cannot probe (another user's, say) is left
// alone, and a file that is not a socket is never touched.
func clearStale(path string) error {
	fi, err := osLstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("control: %w", err)
	}
	if fi.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("control: %s exists and is not a socket (%v); not removing it", path, fi.Mode().Type())
	}
	c, err := net.DialTimeout("unix", path, staleDialTimeout)
	if err == nil {
		c.Close()
		return fmt.Errorf("control: %s: a daemon is already listening on it; not removing it", path)
	}
	if !isRefused(err) {
		return fmt.Errorf("control: %s: cannot tell whether it is stale (%v); not removing it", path, err)
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("control: removing stale socket: %w", err)
	}
	return nil
}

// unixListener reports the path it was asked for, and on Close removes the
// socket file if it is still the one it created.
type unixListener struct {
	*net.UnixListener
	path string
	fi   os.FileInfo
	once sync.Once
}

func (l *unixListener) Addr() net.Addr { return &net.UnixAddr{Name: l.path, Net: "unix"} }

func (l *unixListener) Close() error {
	err := l.UnixListener.Close()
	l.once.Do(func() {
		// Another daemon may have replaced the file since; its socket is
		// not ours to remove.
		if fi, err := osLstat(l.path); err == nil && os.SameFile(fi, l.fi) {
			os.Remove(l.path)
		}
	})
	return err
}

// unixCreds are the transport credentials of a unix connection. There is
// nothing to negotiate on the wire — the socket's mode already decided who
// may connect — so the handshake asks the kernel who the peer is. On the
// client side it also refuses a server running as a uid it does not trust.
type unixCreds struct {
	serverUID *uint32 // client side: a uid trusted besides ours and root's
}

func (unixCreds) ServerHandshake(c net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return c, newUnixAuthInfo(c), nil
}

func (u unixCreds) ClientHandshake(_ context.Context, _ string, c net.Conn) (net.Conn, credentials.AuthInfo, error) {
	if err := checkServerUID(c, u.trusted); err != nil {
		c.Close()
		return nil, nil, err
	}
	return c, newUnixAuthInfo(c), nil
}

// osGetuid is a seam: no test can run a server as another uid without root.
var osGetuid = os.Getuid

// trusted reports whether a server running as uid may receive our commands.
func (u unixCreds) trusted(uid uint32) bool {
	return uid == 0 || int64(uid) == int64(osGetuid()) || (u.serverUID != nil && uid == *u.serverUID)
}

func (unixCreds) Info() credentials.ProtocolInfo {
	return credentials.ProtocolInfo{SecurityProtocol: "unix"}
}

func (u unixCreds) Clone() credentials.TransportCredentials { return u }

func (unixCreds) OverrideServerName(string) error { return nil }

// unixAuthInfo is what a unix connection knows about its peer.
type unixAuthInfo struct {
	credentials.CommonAuthInfo
	uid      uint32
	uidKnown bool
}

func (unixAuthInfo) AuthType() string { return "unix" }

func newUnixAuthInfo(c net.Conn) unixAuthInfo {
	uid, ok := peerUID(c)
	return unixAuthInfo{
		// A unix socket never leaves the machine, so it is as private as the
		// kernel is; this is the level gRPC's own local credentials give it,
		// and what per-RPC credentials that demand privacy check for.
		CommonAuthInfo: credentials.CommonAuthInfo{SecurityLevel: credentials.PrivacyAndIntegrity},
		uid:            uid,
		uidKnown:       ok,
	}
}
