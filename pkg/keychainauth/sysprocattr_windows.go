//go:build windows

package keychainauth

import (
	"os/exec"
	"syscall"
)

// setSysProcAttr configures the command to run detached on Windows.
func setSysProcAttr(cmd *exec.Cmd) {
	// DETACHED_PROCESS = 0x00000008
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: 0x08,
	}
}
