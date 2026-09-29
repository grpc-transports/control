// SPDX-License-Identifier: BSD-3-Clause

//go:build !unix && !windows

package control

import (
	"errors"
	"net"
)

func bindUnix(string) (net.Listener, error) {
	return nil, errors.New("control: unix sockets are not supported on this platform")
}

func isRefused(error) bool { return false }
