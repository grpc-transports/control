// SPDX-License-Identifier: BSD-3-Clause

package control

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

const isWindows = runtime.GOOS == "windows"

// absSock is an absolute socket path for Check tests, which never touch it.
func absSock() string {
	if isWindows {
		return `C:\run\admin.sock`
	}
	return "/run/admin.sock"
}

// sockDir is a directory short enough for a socket path: t.TempDir on
// darwin is already close to the 104-byte limit.
func sockDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("", "c")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return d
}

func unixTarget(path string) string {
	if isWindows {
		return "unix:///" + filepath.ToSlash(path)
	}
	return "unix://" + path
}

// wantCaller is what Caller reports for a unix peer that is this process.
func wantCaller() string {
	switch runtime.GOOS {
	case "linux", "darwin", "freebsd":
		return "uid=" + strconv.Itoa(os.Getuid())
	}
	return "unix"
}

// staleSocket leaves a socket file at path with nobody listening on it.
func staleSocket(t *testing.T, path string) {
	t.Helper()
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	l.SetUnlinkOnClose(false)
	l.Close()
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("control: the stale socket is not there: %v", err)
	}
	if fi.Mode()&os.ModeSocket == 0 {
		t.Skipf("this platform does not report a socket file as a socket (%v)", fi.Mode())
	}
}

func TestUnixRoundTrip(t *testing.T) {
	dir := sockDir(t)
	path := filepath.Join(dir, "admin.sock")
	lis, rec := serve(t, Config{Listen: unixTarget(path)})

	if got := lis.Addr().String(); got != path {
		t.Fatalf("Addr = %q, want %q", got, path)
	}
	if got := lis.Addr().Network(); got != "unix" {
		t.Fatalf("Network = %q", got)
	}
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !isWindows {
		if perm := fi.Mode().Perm(); perm != 0o600 {
			t.Fatalf("socket mode %v, want 0600", perm)
		}
	}
	// Nothing is left of the private directory the socket was bound in.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "admin.sock" {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("directory holds %v, want only admin.sock", names)
	}

	cc, err := Dial(ClientConfig{Target: unixTarget(path)})
	if err != nil {
		t.Fatal(err)
	}
	defer cc.Close()
	if err := healthCheck(t, cc); err != nil {
		t.Fatal(err)
	}
	if caller, _ := rec.last(t); caller != wantCaller() {
		t.Fatalf("Caller = %q, want %q", caller, wantCaller())
	}
}

func TestUnixCloseRemovesItsOwnSocketOnly(t *testing.T) {
	path := filepath.Join(sockDir(t), "admin.sock")
	lis, _, err := Listen(Config{Listen: unixTarget(path)})
	if err != nil {
		t.Fatal(err)
	}
	if err := lis.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Close left the socket file: %v", err)
	}
	if err := lis.Close(); err == nil {
		t.Fatal("a second Close reported success")
	}

	// A file somebody else put at the path since is not ours to remove.
	lis, _, err = Listen(Config{Listen: unixTarget(path)})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("theirs"), 0o600); err != nil {
		t.Fatal(err)
	}
	lis.Close()
	if b, err := os.ReadFile(path); err != nil || string(b) != "theirs" {
		t.Fatalf("Close removed a file it did not create: %q, %v", b, err)
	}
}

func TestUnixStaleSocketIsRemoved(t *testing.T) {
	path := filepath.Join(sockDir(t), "admin.sock")
	staleSocket(t, path)
	_, rec := serve(t, Config{Listen: unixTarget(path)})
	cc, err := Dial(ClientConfig{Target: unixTarget(path)})
	if err != nil {
		t.Fatal(err)
	}
	defer cc.Close()
	if err := healthCheck(t, cc); err != nil {
		t.Fatalf("the new listener does not answer where the stale socket was: %v", err)
	}
	rec.last(t)
}

func TestUnixLiveSocketIsNotStolen(t *testing.T) {
	path := filepath.Join(sockDir(t), "admin.sock")
	live, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer live.Close()
	accepted := make(chan struct{})
	go func() {
		for {
			c, err := live.Accept()
			if err != nil {
				return
			}
			c.Close()
			accepted <- struct{}{}
		}
	}()

	lis, _, err := Listen(Config{Listen: unixTarget(path)})
	if err == nil {
		lis.Close()
		t.Fatal("Listen took over a live daemon's socket")
	}
	if !strings.Contains(err.Error(), path) || !strings.Contains(err.Error(), "already listening") {
		t.Fatalf("err = %q, want it to name %s and say it is live", err, path)
	}
	<-accepted // the probe itself
	c, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("the live daemon's socket no longer answers: %v", err)
	}
	c.Close()
	<-accepted
}

func TestUnixNonSocketIsNeverRemoved(t *testing.T) {
	dir := sockDir(t)
	file := filepath.Join(dir, "admin.sock")
	if err := os.WriteFile(file, []byte("precious"), 0o600); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(dir, "adir")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{file, sub} {
		lis, _, err := Listen(Config{Listen: unixTarget(path)})
		if err == nil {
			lis.Close()
			t.Fatalf("Listen replaced %s", path)
		}
		if !strings.Contains(err.Error(), "not a socket") {
			t.Fatalf("err = %q", err)
		}
	}
	if b, err := os.ReadFile(file); err != nil || string(b) != "precious" {
		t.Fatalf("the regular file changed: %q, %v", b, err)
	}
	if fi, err := os.Stat(sub); err != nil || !fi.IsDir() {
		t.Fatalf("the directory changed: %v", err)
	}
}

func TestUnixBindErrors(t *testing.T) {
	dir := sockDir(t)
	for name, path := range map[string]string{
		"no parent": filepath.Join(dir, "missing", "admin.sock"),
		"too long":  filepath.Join(dir, strings.Repeat("x", 120)+".sock"),
	} {
		t.Run(name, func(t *testing.T) {
			lis, _, err := Listen(Config{Listen: unixTarget(path)})
			if err == nil {
				lis.Close()
				t.Fatalf("Listen(%s) succeeded", path)
			}
			if !strings.HasPrefix(err.Error(), "control: ") {
				t.Fatalf("err = %q", err)
			}
		})
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Fatalf("a failed Listen left %d entries behind", len(entries))
	}
}

func TestClearStaleLstatError(t *testing.T) {
	boom := errors.New("boom")
	orig := osLstat
	osLstat = func(string) (os.FileInfo, error) { return nil, boom }
	defer func() { osLstat = orig }()
	if err := clearStale(absSock()); !errors.Is(err, boom) {
		t.Fatalf("err = %v, want boom", err)
	}
}

func TestListenUnixCheckFirst(t *testing.T) {
	_, _, err := Listen(Config{Listen: unixTarget(absSock()), TLSCertFile: "c"})
	if err == nil || !strings.Contains(err.Error(), "must be empty") {
		t.Fatalf("err = %v", err)
	}
}
