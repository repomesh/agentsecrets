package keychainauth

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
)

// activeSession holds the in-memory session state for the current process.
// The session token is NEVER written to disk, logged, or exposed to the agent.
var (
	conn               net.Conn
	activeSessionToken string
	sessionMu          sync.Mutex
	initialized        bool
)

// Init connects to the keychain-auth daemon and performs the SESSION_INIT handshake.
//
// This must be called once per process lifetime before any GetSecret() call.
// The session token is stored in memory only. The binary hash is computed fresh
// on every call — it is never cached between invocations.
//
// If the daemon is not running, Init returns a *DaemonNotRunningError with
// a user-facing message explaining how to fix it.
func Init() error {
	sessionMu.Lock()
	defer sessionMu.Unlock()

	if initialized {
		return nil
	}

	sockPath := SocketPath()

	// Step 1: Check socket exists before attempting connection
	if _, err := os.Stat(sockPath); os.IsNotExist(err) {
		return &DaemonNotRunningError{SocketPath: sockPath, Cause: err}
	}

	// Step 2: Connect to the Unix socket
	c, err := net.Dial("unix", sockPath)
	if err != nil {
		return &DaemonNotRunningError{SocketPath: sockPath, Cause: err}
	}

	// Step 3: Compute self-identity (fresh every time, never cached)
	// Resolve symlinks so the path matches what the daemon sees via
	// /proc/PID/exe (Linux) or proc_pidpath (macOS). On macOS, Homebrew
	// installs to Cellar and symlinks into /opt/homebrew/bin — without
	// resolving, the daemon sees the Cellar path but we'd send the symlink.
	selfPath, err := os.Executable()
	if err != nil {
		c.Close()
		return fmt.Errorf("keychainauth: cannot determine own executable path: %w", err)
	}
	selfPath, err = filepath.EvalSymlinks(selfPath)
	if err != nil {
		c.Close()
		return fmt.Errorf("keychainauth: cannot resolve executable symlinks: %w", err)
	}

	selfHash, err := hashBinary(selfPath)
	if err != nil {
		c.Close()
		return fmt.Errorf("keychainauth: cannot hash own binary: %w", err)
	}

	// Step 4: Send SESSION_INIT
	enc := json.NewEncoder(c)
	if err := enc.Encode(sessionInitMsg{
		Type:            typeSessionInit,
		PID:             os.Getpid(),
		BinaryPath:      selfPath,
		BinaryHash:      selfHash,
		ProtocolVersion: "1",
	}); err != nil {
		c.Close()
		return fmt.Errorf("keychainauth: failed to send SESSION_INIT: %w", err)
	}

	// Step 5: Read response
	scanner := bufio.NewScanner(c)
	scanner.Buffer(make([]byte, 0, 64*1024), 64*1024)
	if !scanner.Scan() {
		c.Close()
		if err := scanner.Err(); err != nil {
			return fmt.Errorf("keychainauth: failed to read session response: %w", err)
		}
		return fmt.Errorf("keychainauth: connection closed before session response")
	}

	var env envelope
	raw := scanner.Bytes()
	if err := json.Unmarshal(raw, &env); err != nil {
		c.Close()
		return fmt.Errorf("keychainauth: invalid response from daemon: %w", err)
	}

	switch env.Type {
	case typeSessionAccepted:
		var accepted sessionAcceptedMsg
		if err := json.Unmarshal(raw, &accepted); err != nil {
			c.Close()
			return fmt.Errorf("keychainauth: malformed SESSION_ACCEPTED: %w", err)
		}
		activeSessionToken = accepted.SessionToken
		conn = c
		initialized = true
		return nil

	case typeSessionRejected:
		c.Close()
		var rejected sessionRejectedMsg
		if err := json.Unmarshal(raw, &rejected); err != nil {
			return fmt.Errorf("keychainauth: malformed SESSION_REJECTED: %w", err)
		}
		return &SessionRejectedError{Reason: rejected.Reason}

	default:
		c.Close()
		return fmt.Errorf("keychainauth: unexpected response type %q", env.Type)
	}
}

// GetSecret sends a SECRET_REQUEST to keychain-auth and returns the plaintext value.
//
// The key is the bare secret name (e.g., "OPENAI_API_KEY"). The projectID and
// environment are sent alongside it — keychain-auth constructs the full
// {projectID}:{environment}:{key} keychain key internally.
//
// The returned value should be used immediately and not stored in any persistent
// variable, struct field, log, or error message.
func GetSecret(projectID, environment, key string) (string, error) {
	sessionMu.Lock()
	defer sessionMu.Unlock()

	if !initialized || activeSessionToken == "" {
		return "", fmt.Errorf("keychainauth: no active session — call Init() first")
	}

	// Send SECRET_REQUEST
	enc := json.NewEncoder(conn)
	if err := enc.Encode(secretRequestMsg{
		Type:         typeSecretRequest,
		SessionToken: activeSessionToken,
		ProjectID:    projectID,
		Environment:  environment,
		Key:          key,
	}); err != nil {
		return "", fmt.Errorf("keychainauth: failed to send SECRET_REQUEST: %w", err)
	}

	// Read response (single line of newline-delimited JSON)
	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 0, 64*1024), 64*1024)
	if !scanner.Scan() {
		// Connection dropped — do not reconnect, surface error
		initialized = false
		activeSessionToken = ""
		if err := scanner.Err(); err != nil {
			return "", fmt.Errorf("keychainauth: connection lost during secret read: %w", err)
		}
		return "", fmt.Errorf("keychainauth: connection closed by daemon")
	}

	var env envelope
	raw := scanner.Bytes()
	if err := json.Unmarshal(raw, &env); err != nil {
		return "", fmt.Errorf("keychainauth: invalid response: %w", err)
	}

	switch env.Type {
	case typeSecretResponse:
		var resp secretResponseMsg
		if err := json.Unmarshal(raw, &resp); err != nil {
			return "", fmt.Errorf("keychainauth: malformed SECRET_RESPONSE: %w", err)
		}
		return resp.Value, nil

	case typeSecretDenied:
		var denied secretDeniedMsg
		if err := json.Unmarshal(raw, &denied); err != nil {
			return "", fmt.Errorf("keychainauth: malformed SECRET_DENIED: %w", err)
		}
		return "", &SecretDeniedError{Key: denied.Key, Reason: denied.Reason}

	default:
		return "", fmt.Errorf("keychainauth: unexpected response type %q", env.Type)
	}
}

// Close tears down the Unix socket connection to keychain-auth.
// Safe to call multiple times. Should be deferred from main or called
// in a signal handler.
func Close() {
	sessionMu.Lock()
	defer sessionMu.Unlock()

	if conn != nil {
		conn.Close()
		conn = nil
	}
	activeSessionToken = ""
	initialized = false
}

// IsAvailable checks whether the keychain-auth socket file exists on disk.
// This is a quick probe — it does not attempt a connection.
func IsAvailable() bool {
	_, err := os.Stat(SocketPath())
	return err == nil
}

// IsInitialized returns true if a session has been successfully established.
func IsInitialized() bool {
	sessionMu.Lock()
	defer sessionMu.Unlock()
	return initialized
}

// --- Internal helpers ---

// hashBinary computes the SHA-256 hash of a file and returns it in the
// "sha256:<hex>" format expected by keychain-auth.
func hashBinary(path string) (string, error) {
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
