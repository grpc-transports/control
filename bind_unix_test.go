// SPDX-License-Identifier: BSD-3-Clause

//go:build unix

package control

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// The socket is unreachable by anyone else before its chmod: at the moment
// of the chmod it exists only inside a 0700 directory, and not yet at the
// requested path. That holds whatever the umask, so the test widens it to 0.
func TestUnixNeverExposed(t *testing.T) {
	old := syscall.Umask(0)
	defer syscall.Umask(old)

	path := filepath.Join(sockDir(t), "admin.sock")
	var checked bool
	orig := osChmod
	osChmod = func(name string, mode os.FileMode) error {
		checked = true
		di, err := os.Stat(filepath.Dir(name))
		if err != nil {
			t.Fatal(err)
		}
		if perm := di.Mode().Perm(); perm != 0o700 {
			t.Errorf("socket bound in a directory with mode %v, want 0700", perm)
		}
		if filepath.Dir(filepath.Dir(name)) != filepath.Dir(path) {
			t.Errorf("socket bound in %s, not next to %s", name, path)
		}
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("the socket is at %s before its chmod", path)
		}
		return orig(name, mode)
	}
	defer func() { osChmod = orig }()

	lis, _, err := Listen(Config{Listen: unixTarget(path)})
	if err != nil {
		t.Fatal(err)
	}
	defer lis.Close()
	if !checked {
		t.Fatal("chmod was never called")
	}
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("socket mode %v under umask 0, want 0600", perm)
	}
}

// A file that appears at the path between the stale check and the link is
// not replaced: link(2) refuses, for real, here.
func TestUnixAppearedWhileBinding(t *testing.T) {
	path := filepath.Join(sockDir(t), "admin.sock")
	orig := osLink
	osLink = func(o, n string) error {
		if err := os.WriteFile(n, []byte("late"), 0o600); err != nil {
			t.Fatal(err)
		}
		return orig(o, n)
	}
	defer func() { osLink = orig }()
	lis, _, err := Listen(Config{Listen: unixTarget(path)})
	if err == nil {
		lis.Close()
		t.Fatal("Listen replaced a file that appeared while binding")
	}
	if !strings.Contains(err.Error(), "appeared while binding") {
		t.Fatalf("err = %q", err)
	}
	if b, _ := os.ReadFile(path); string(b) != "late" {
		t.Fatalf("the late file changed: %q", b)
	}
}

func TestUnixPublishErrors(t *testing.T) {
	boom := errors.New("boom")
	for name, set := range map[string]func() func(){
		"chmod": func() func() {
			o := osChmod
			osChmod = func(string, os.FileMode) error { return boom }
			return func() { osChmod = o }
		},
		"link": func() func() {
			o := osLink
			osLink = func(string, string) error { return boom }
			return func() { osLink = o }
		},
		"bind": func() func() {
			o := netListenUnix
			netListenUnix = func(string, *net.UnixAddr) (*net.UnixListener, error) { return nil, boom }
			return func() { netListenUnix = o }
		},
		"lstat after link": func() func() {
			o := osLstat
			n := 0
			osLstat = func(p string) (os.FileInfo, error) {
				n++
				if n == 1 { // clearStale's
					return o(p)
				}
				return nil, boom
			}
			return func() { osLstat = o }
		},
	} {
		t.Run(name, func(t *testing.T) {
			dir := sockDir(t)
			path := filepath.Join(dir, "admin.sock")
			restore := set()
			lis, _, err := Listen(Config{Listen: unixTarget(path)})
			restore()
			if err == nil {
				lis.Close()
				t.Fatal("Listen succeeded")
			}
			if !errors.Is(err, boom) {
				t.Fatalf("err = %v, want boom", err)
			}
			if entries, _ := os.ReadDir(dir); len(entries) != 0 {
				t.Fatalf("a failed Listen left %d entries behind", len(entries))
			}
		})
	}
}

// A socket this process cannot connect to may be another user's live
// daemon: it is left alone. Control: once it can be probed, it is replaced.
func TestUnixUnprobeableSocketIsKept(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root connects to any socket regardless of its mode")
	}
	path := filepath.Join(sockDir(t), "admin.sock")
	staleSocket(t, path)
	if err := os.Chmod(path, 0); err != nil {
		t.Fatal(err)
	}
	lis, _, err := Listen(Config{Listen: unixTarget(path)})
	if err == nil {
		lis.Close()
		t.Fatal("Listen replaced a socket it could not probe")
	}
	if !strings.Contains(err.Error(), "cannot tell whether it is stale") {
		t.Fatalf("err = %q", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	lis, _, err = Listen(Config{Listen: unixTarget(path)})
	if err != nil {
		t.Fatalf("control: %v", err)
	}
	lis.Close()
}

func TestUnixStaleNotRemovable(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root removes files from any directory")
	}
	dir := filepath.Join(sockDir(t), "d")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "admin.sock")
	staleSocket(t, path)
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(dir, 0o700)
	lis, _, err := Listen(Config{Listen: unixTarget(path)})
	if err == nil {
		lis.Close()
		t.Fatal("Listen succeeded in a read-only directory")
	}
	if !strings.Contains(err.Error(), "removing stale socket") {
		t.Fatalf("err = %q", err)
	}
}

func TestIsRefused(t *testing.T) {
	if !isRefused(&net.OpError{Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}) {
		t.Fatal("ECONNREFUSED not recognised")
	}
	if isRefused(syscall.EACCES) {
		t.Fatal("EACCES taken for refused")
	}
}

// A path longer than a socket address holds is refused with the reason,
// and so is one in a directory whose temporary name while binding would
// not fit, rather than failing with a bare EINVAL.
func TestUnixPathLimits(t *testing.T) {
	dir := sockDir(t)
	fill := func(base string, n int) string { return base + strings.Repeat("x", n-len(base)) }

	long := fill(dir+"/", sunPathMax+1)
	if _, _, err := Listen(Config{Listen: unixTarget(long)}); err == nil || !strings.Contains(err.Error(), "at most") {
		t.Fatalf("%d-byte path: err = %v", len(long), err)
	}

	deep := fill(dir+"/", sunPathMax-5)
	if err := os.Mkdir(deep, 0o700); err != nil {
		t.Fatal(err)
	}
	path := deep + "/a"
	if _, _, err := Listen(Config{Listen: unixTarget(path)}); err == nil || !strings.Contains(err.Error(), "while binding it as") {
		t.Fatalf("%d-byte path in a %d-byte directory: err = %v", len(path), len(deep), err)
	}
	if entries, _ := os.ReadDir(deep); len(entries) != 0 {
		t.Fatalf("a refused Listen left %d entries behind", len(entries))
	}

	// Control: a path of exactly the limit, in a short directory, is served
	// and can be connected to.
	edge := fill(dir+"/", sunPathMax)
	lis, _, err := Listen(Config{Listen: unixTarget(edge)})
	if err != nil {
		t.Fatalf("control: %d-byte path: %v", len(edge), err)
	}
	defer lis.Close()
	c, err := net.Dial("unix", edge)
	if err != nil {
		t.Fatalf("a %d-byte path was bound but cannot be connected to: %v", len(edge), err)
	}
	c.Close()
}
