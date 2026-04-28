package keychainauth

import "fmt"

// SessionRejectedError is returned when keychain-auth rejects a SESSION_INIT request.
// The Reason field matches the protocol's RejectReason constants.
type SessionRejectedError struct {
	Reason rejectReason
}

func (e *SessionRejectedError) Error() string {
	return fmt.Sprintf("keychain-auth rejected session: %s", e.Reason)
}

// SecretDeniedError is returned when keychain-auth denies a SECRET_REQUEST.
type SecretDeniedError struct {
	Key    string
	Reason rejectReason
}

func (e *SecretDeniedError) Error() string {
	return fmt.Sprintf("keychain-auth denied access to %q: %s", e.Key, e.Reason)
}

// DaemonNotRunningError is returned when the keychain-auth socket does not exist
// or the connection is refused.
type DaemonNotRunningError struct {
	SocketPath string
	Cause      error
}

func (e *DaemonNotRunningError) Error() string {
	return "keychain-auth daemon is not running"
}

func (e *DaemonNotRunningError) Unwrap() error {
	return e.Cause
}

// UserMessage returns the full user-facing error text for a rejection reason.
// These messages are specified in the integration spec and should not be changed
// without updating the spec.
func UserMessage(err error) string {
	switch e := err.(type) {
	case *SessionRejectedError:
		return sessionRejectMessage(e.Reason)
	case *SecretDeniedError:
		return secretDenyMessage(e.Key, e.Reason)
	case *DaemonNotRunningError:
		return daemonNotRunningMessage(e.SocketPath)
	default:
		return err.Error()
	}
}

func sessionRejectMessage(reason rejectReason) string {
	switch reason {
	case reasonHashMismatch:
		return "Security check failed: AgentSecrets binary has been modified. Reinstall to continue."
	case reasonInvalidPID:
		return "keychain-auth could not verify this process. Try again or reinstall AgentSecrets."
	case reasonPathMismatch:
		return "keychain-auth rejected this binary path. Ensure AgentSecrets is installed in the expected location."
	case reasonUnsupportedProtocol:
		return "keychain-auth version is incompatible. Run: keychain-auth upgrade"
	default:
		return fmt.Sprintf("keychain-auth rejected the session: %s", reason)
	}
}

func secretDenyMessage(key string, reason rejectReason) string {
	switch reason {
	case reasonSecretNotFound:
		return fmt.Sprintf("Secret %q not found in keychain — run 'agentsecrets secrets pull' to sync from cloud", key)
	case reasonSessionExpired:
		return "Session expired — the AgentSecrets process may have been replaced. Restart and try again."
	case reasonSessionInvalidated:
		return "Session invalidated — the AgentSecrets binary was modified while running. Restart and try again."
	case reasonUnknownSession:
		return "No active keychain-auth session. This is a bug — please report it."
	case reasonInvalidKey:
		return fmt.Sprintf("Invalid key name %q — key names must not contain slashes, colons, or dots", key)
	default:
		return fmt.Sprintf("keychain-auth denied access to %q: %s", key, reason)
	}
}

func daemonNotRunningMessage(socketPath string) string {
	return fmt.Sprintf(`keychain-auth daemon is not running.

AgentSecrets requires keychain-auth to read secrets securely.
This is a one-time setup that protects your credentials from unauthorized access.

Run this to set it up:
  agentsecrets init

Or start it manually:
  keychain-auth start

Socket expected at: %s`, socketPath)
}
