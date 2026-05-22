package keychainauth

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"time"
)

// SocketPath returns the keychain-auth Unix socket path.
// It uses platform-specific, user-writable directories to avoid permission issues.
func SocketPath() string {
	if runtime.GOOS == "darwin" {
		return filepath.Join(os.Getenv("HOME"), "Library", "Application Support", "keychain-auth", "agent.sock")
	}

	// Linux / WSL
	runtimeDir := os.Getenv("XDG_RUNTIME_DIR")
	if runtimeDir != "" {
		// Verify the directory actually exists (WSL often exports this env var but the directory
		// isn't created by systemd, leading to permission denied when we try to MkdirAll later).
		if info, err := os.Stat(runtimeDir); err != nil || !info.IsDir() {
			runtimeDir = ""
		}
	}
	
	if runtimeDir == "" {
		// Fallback to home-based cache dir
		runtimeDir = filepath.Join(os.Getenv("HOME"), ".cache")
	}
	return filepath.Join(runtimeDir, "keychain-auth", "agent.sock")
}

// connectionProbeTimeout is how long we wait to detect an immediate rejection
// from the daemon during Init(). Short enough to not feel slow, long enough
// for the daemon to respond if it wants to deny us.
var connectionProbeTimeout = 200 * time.Millisecond

// timeNow and timeZero are vars to allow test overrides.
var (
	timeNow  = time.Now
	timeZero time.Time
)

// dialCLOEXEC connects to a Unix domain socket with the SOCK_CLOEXEC flag set.
// This prevents the file descriptor from being inherited by child processes,
// which is critical for `agentsecrets env` and `agentsecrets exec` commands
// that spawn child processes.
func dialCLOEXEC(sockPath string) (net.Conn, error) {
	if runtime.GOOS == "windows" {
		// Windows doesn't use Unix sockets — fall back to standard dial.
		// Named pipe support can be added later.
		return net.Dial("unix", sockPath)
	}

	// Create socket with SOCK_CLOEXEC
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
