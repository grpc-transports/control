// SPDX-License-Identifier: BSD-3-Clause

//go:build linux || darwin || freebsd

package control

import (
	"errors"
	"net"
	"path/filepath"
	"syscall"
	"testing"
)

func TestPeerUIDFailures(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	if _, ok := peerUID(a); ok {
		t.Fatal("a pipe has a peer uid")
	}
	if _, ok := peerUID(noRawConn{a}); ok {
		t.Fatal("a conn without a raw conn has a peer uid")
	}

	path := filepath.Join(sockDir(t), "p.sock")
	l, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	c, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := peerUID(c); !ok {
		t.Fatal("control: an open unix conn has no peer uid")
	}
	c.Close()
	if _, ok := peerUID(c); ok {
		t.Fatal("a closed conn has a peer uid")
	}
	if _, ok := sockUID(-1); ok {
		t.Fatal("fd -1 has a peer uid")
	}
}

// noRawConn is a syscall.Conn whose SyscallConn fails.
type noRawConn struct{ net.Conn }

func (noRawConn) SyscallConn() (syscall.RawConn, error) { return nil, errors.New("no raw conn") }
