package keychainauth

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// AutoSetup performs the full keychain-auth setup sequence:
//  1. Ensures keychain-auth is installed (installs if missing)
//  2. Registers the AgentSecrets binary hash with keychain-auth
//  3. Ensures the daemon is running (starts if not)
//
// This is designed to be invisible to the user during normal operation.
// When called during an upgrade (first secret read after update), the caller
// should display a spinner and explanatory message.
//
// Returns nil if everything is ready, or an error describing what failed.
func AutoSetup() error {
	kcPath, err := EnsureInstalled()
	if err != nil {
		return fmt.Errorf("keychain-auth setup: %w", err)
	}

	if err := EnsureRegistered(kcPath); err != nil {
		return fmt.Errorf("keychain-auth setup: %w", err)
	}

	if err := EnsureDaemonRunning(kcPath); err != nil {
		return fmt.Errorf("keychain-auth setup: %w", err)
	}

	return nil
}

// EnsureInstalled checks if keychain-auth is in PATH.
// If not found, attempts to install it via the platform's package manager.
// Returns the absolute path to the keychain-auth binary.
func EnsureInstalled() (string, error) {
	// Check if already installed
	path, err := exec.LookPath("keychain-auth")
	if err == nil {
		return path, nil
	}

	// Not installed — attempt platform-specific installation
	switch runtime.GOOS {
	case "darwin":
		return installViaBrew()
	case "linux":
		// Try Homebrew first (Linuxbrew), then fall back to instructions
		if _, err := exec.LookPath("brew"); err == nil {
			return installViaBrew()
		}
		return "", fmt.Errorf(
			"keychain-auth is not installed.\n\n" +
				"Install it with Homebrew:\n" +
				"  brew install The-17/tap/keychain-auth\n\n" +
				"Or download from GitHub:\n" +
				"  https://github.com/The-17/keychain-auth/releases",
		)
	default:
		return "", fmt.Errorf("keychain-auth is not supported on %s yet", runtime.GOOS)
	}
}

// installViaBrew installs keychain-auth via Homebrew and returns the binary path.
func installViaBrew() (string, error) {
	cmd := exec.Command("brew", "install", "The-17/tap/keychain-auth")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf(
			"failed to install keychain-auth via Homebrew: %w\n\n"+
				"You can install it manually:\n"+
				"  brew tap The-17/tap\n"+
				"  brew install keychain-auth",
			err,
		)
	}

	path, err := exec.LookPath("keychain-auth")
	if err != nil {
		return "", fmt.Errorf("keychain-auth installed but not found in PATH: %w", err)
	}
	return path, nil
}

// EnsureRegistered registers the current AgentSecrets binary with keychain-auth.
// This tells keychain-auth "this binary is trusted" by recording its SHA-256 hash.
//
// On upgrade, the new hash must be registered before the first secret read.
// This function is idempotent — re-registering the same hash is a no-op.
func EnsureRegistered(keychainAuthPath string) error {
	selfPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("cannot determine own binary path: %w", err)
	}
	// Resolve symlinks so we register the real physical path, not a symlink.
	// On macOS, Homebrew symlinks /opt/homebrew/bin/agentsecrets → Cellar/…/bin/agentsecrets.
	// The daemon resolves via proc_pidpath to the Cellar path, so we must register that.
	selfPath, err = filepath.EvalSymlinks(selfPath)
	if err != nil {
		return fmt.Errorf("cannot resolve binary symlinks: %w", err)
	}

	cmd := exec.Command(keychainAuthPath, "register", selfPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to register with keychain-auth: %w\nOutput: %s", err, strings.TrimSpace(string(output)))
	}

	return nil
}

// EnsureDaemonRunning checks if the keychain-auth daemon is running by probing
// the socket. If the socket doesn't exist, it attempts to start the daemon
// using the platform's service manager.
func EnsureDaemonRunning(keychainAuthPath string) error {
	if IsAvailable() {
		return nil
	}

	switch runtime.GOOS {
	case "darwin":
		return startDaemonMacOS(keychainAuthPath)
	case "linux":
		return startDaemonLinux(keychainAuthPath)
	default:
		return fmt.Errorf("cannot start keychain-auth daemon on %s", runtime.GOOS)
	}
}

// RestartDaemon kills any running keychain-auth daemon and starts a fresh one.
// This is needed after re-registering a binary so the daemon picks up the new hash.
func RestartDaemon() error {
	// Kill existing daemon
	_ = exec.Command("pkill", "-f", "keychain-auth").Run()

	// Remove stale socket
	sockPath := SocketPath()
	_ = os.Remove(sockPath)

	// Wait a moment for the process to die
	time.Sleep(200 * time.Millisecond)

	// Find keychain-auth and start fresh
	kcPath, err := exec.LookPath("keychain-auth")
	if err != nil {
		return fmt.Errorf("keychain-auth not found in PATH: %w", err)
	}
	return startDirect(kcPath)
}

// startDaemonMacOS starts keychain-auth via launchctl on macOS.
func startDaemonMacOS(keychainAuthPath string) error {
	// Try launchctl first (preferred — survives reboots)
	plistName := "io.keychainauth.daemon"
	cmd := exec.Command("launchctl", "start", plistName)
	if err := cmd.Run(); err == nil {
		return waitForSocket()
	}

	// Fallback: try loading the plist if it exists
	home, _ := os.UserHomeDir()
	plistPath := home + "/Library/LaunchAgents/" + plistName + ".plist"
	if _, err := os.Stat(plistPath); err == nil {
		cmd = exec.Command("launchctl", "load", plistPath)
		if err := cmd.Run(); err == nil {
			return waitForSocket()
		}
	}

	// Last resort: start directly
	return startDirect(keychainAuthPath)
}

// startDaemonLinux starts keychain-auth via systemd on Linux.
func startDaemonLinux(keychainAuthPath string) error {
	// Try systemd user service first
	cmd := exec.Command("systemctl", "--user", "start", "keychain-auth")
	if err := cmd.Run(); err == nil {
		return waitForSocket()
	}

	// Try enabling and starting
	cmd = exec.Command("systemctl", "--user", "enable", "--now", "keychain-auth")
	if err := cmd.Run(); err == nil {
		return waitForSocket()
	}

	// Last resort: start directly
	return startDirect(keychainAuthPath)
}

// startDirect starts keychain-auth as a background process. This is the fallback
// when the system service manager is not configured.
func startDirect(keychainAuthPath string) error {
	sockPath := SocketPath()

	// Ensure the socket directory exists
	if err := os.MkdirAll(filepath.Dir(sockPath), 0700); err != nil {
		return fmt.Errorf("failed to create socket directory: %w", err)
	}

	// Pass --socket so even older keychain-auth binaries that default to
	// /var/run/ will use the user-writable path instead.
	cmd := exec.Command(keychainAuthPath, "start", "--socket", sockPath)
	cmd.Stdout = nil
	cmd.Stderr = nil
	cmd.Stdin = nil

	// Start as detached process
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start keychain-auth daemon: %w", err)
	}

	// Don't wait for the process — it's a daemon
	go func() { _ = cmd.Wait() }()

	return waitForSocket()
}

// waitForSocket polls for the socket file to appear, with a short timeout.
func waitForSocket() error {
	for i := 0; i < 30; i++ {
		if IsAvailable() {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("keychain-auth daemon started but socket not available after 3 seconds")
}


// computeHash returns the SHA-256 hash of a file in "sha256:<hex>" format.
func computeHash(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}
