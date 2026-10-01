// SPDX-License-Identifier: BSD-3-Clause

//go:build linux || darwin || freebsd

package control

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Dial must refuse a server that runs as a uid it does not trust: an
// impostor that bound the socket first would otherwise get the commands.
// No test can run a server as another uid without root, so the client is
// made to believe it runs as someone else.
func TestDialRefusesUntrustedServerUID(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root: a server running as root is always trusted")
	}
	path := filepath.Join(sockDir(t), "admin.sock")
	serve(t, Config{Listen: unixTarget(path)})
	me := uint32(os.Getuid())
	osGetuid = func() int { return int(me) + 1 }
	t.Cleanup(func() { osGetuid = os.Getuid })

	cc, err := Dial(ClientConfig{Target: unixTarget(path)})
	if err != nil {
		t.Fatal(err)
	}
	defer cc.Close()
	if err := healthCheck(t, cc); err == nil || !strings.Contains(err.Error(), "runs as uid") {
		t.Fatalf("RPC to a server of an untrusted uid: %v, want a refusal", err)
	}

	// Positive control: the same server, its uid named in ServerUID.
	cc2, err := Dial(ClientConfig{Target: unixTarget(path), ServerUID: &me})
	if err != nil {
		t.Fatal(err)
	}
	defer cc2.Close()
	if err := healthCheck(t, cc2); err != nil {
		t.Fatalf("RPC with ServerUID = %d: %v", me, err)
	}
}

// A real socket served by another, unprivileged uid: the system D-Bus
// (messagebus) on Linux, mDNSResponder (_mdnsresponder) on darwin. Before
// the fix Dial sent it HTTP/2 and the RPC failed only for want of an answer.
func TestDialRefusesForeignSocket(t *testing.T) {
	var bus string
	var uid uint32
	for _, p := range []string{"/run/dbus/system_bus_socket", "/var/run/mDNSResponder"} {
		c, err := net.Dial("unix", p)
		if err != nil {
			continue
		}
		u, ok := peerUID(c)
		c.Close()
		if ok && u != 0 && int(u) != os.Getuid() {
			bus, uid = p, u
			break
		}
	}
	if bus == "" {
		t.Skip("no socket served by another unprivileged uid here")
	}
	cc, err := Dial(ClientConfig{Target: "unix://" + bus})
	if err != nil {
		t.Fatal(err)
	}
	defer cc.Close()
	err = healthCheck(t, cc)
	if err == nil || !strings.Contains(err.Error(), "runs as uid") {
		t.Fatalf("RPC to %s (uid %d): %v, want the uid refusal", bus, uid, err)
	}
}

func TestCheckServerUIDUnreadable(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	err := checkServerUID(a, func(uint32) bool { return true })
	if err == nil || !strings.Contains(err.Error(), "cannot read the uid") {
		t.Fatalf("a conn without peer credentials: %v, want a refusal", err)
	}
}
