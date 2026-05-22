//go:build linux

package keychainauth

import (
	"fmt"
	"net"
	"os"
	"syscall"
)

// dialCLOEXEC connects to a Unix domain socket with the SOCK_CLOEXEC flag set.
// This prevents the file descriptor from being inherited by child processes.
func dialCLOEXEC(sockPath string) (net.Conn, error) {
	fd, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		// Fallback for older kernels that don't support SOCK_CLOEXEC
		return net.Dial("unix", sockPath)
	}

	addr := &syscall.SockaddrUnix{Name: sockPath}
	if err := syscall.Connect(fd, addr); err != nil {
		syscall.Close(fd)
		return nil, err
	}

	// Convert raw fd to a net.Conn
	file := os.NewFile(uintptr(fd), sockPath)
	if file == nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("failed to wrap socket fd")
	}

	c, err := net.FileConn(file)
	file.Close() // FileConn dups the fd, so close the original
	if err != nil {
		return nil, err
	}

	return c, nil
}
