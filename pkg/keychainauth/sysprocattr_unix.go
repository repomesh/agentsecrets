//go:build !windows

package keychainauth

import (
	"os/exec"
	"syscall"
)

// setSysProcAttr configures the command to run in a new session
// so the daemon survives parent CLI exit on Unix.
func setSysProcAttr(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid: true,
	}
}
