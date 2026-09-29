// SPDX-License-Identifier: BSD-3-Clause

package control

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestWindowsBindLstatError(t *testing.T) {
	boom := errors.New("boom")
	orig := osLstat
	osLstat = func(string) (os.FileInfo, error) { return nil, boom }
	defer func() { osLstat = orig }()
	if _, err := bindUnix(filepath.Join(t.TempDir(), "a.sock")); !errors.Is(err, boom) {
		t.Fatalf("err = %v, want boom", err)
	}
}

func TestWindowsIsRefused(t *testing.T) {
	if !isRefused(wsaeconnrefused) {
		t.Fatal("WSAECONNREFUSED not recognised")
	}
	if isRefused(syscall.Errno(5)) {
		t.Fatal("ERROR_ACCESS_DENIED taken for refused")
	}
}
