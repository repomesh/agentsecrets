//go:build windows

package keychainauth

import (
	"net"
)

// dialCLOEXEC connects to a socket on Windows.
func dialCLOEXEC(sockPath string) (net.Conn, error) {
	return net.Dial("unix", sockPath)
}
