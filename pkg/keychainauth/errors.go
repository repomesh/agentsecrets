package keychainauth

import "fmt"

// DaemonDeniedError is returned when keychain-auth denies a connection or request.
type DaemonDeniedError struct {
	Reason reasonCode
}

func (e *DaemonDeniedError) Error() string {
	return fmt.Sprintf("keychain-auth denied request: %s", e.Reason)
}

// IsUnregistered returns true if the denial was due to an unregistered binary.
func (e *DaemonDeniedError) IsUnregistered() bool {
	return e.Reason == reasonUnregisteredBinary
}

// IsHashMismatch returns true if the denial was due to a binary hash mismatch during fork.
func (e *DaemonDeniedError) IsHashMismatch() bool {
	return e.Reason == reasonHashMismatch
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

// UserMessage returns the full user-facing error text for keychain-auth errors.
// These messages should explain what happened and what to do next.
func UserMessage(err error) string {
	switch e := err.(type) {
	case *DaemonDeniedError:
		return deniedMessage(e.Reason)
	case *DaemonNotRunningError:
		return daemonNotRunningMessage(e.SocketPath)
	default:
		return err.Error()
	}
}

func deniedMessage(reason reasonCode) string {
	switch reason {
	case reasonUnregisteredBinary:
		return "This AgentSecrets binary is not yet registered with keychain-auth.\n" +
			"This usually resolves automatically. If it persists, run:\n" +
			"  agentsecrets init"
	case reasonHashMismatch:
		return "Security check failed: the AgentSecrets binary has changed since it was registered.\n" +
			"This usually resolves automatically after an upgrade. If it persists, run:\n" +
			"  agentsecrets init"
	case reasonActionNotInPolicy:
		return "keychain-auth policy does not allow this operation for AgentSecrets.\n" +
			"Check your keychain-auth configuration."
	case reasonServiceNotAllowed:
		return "keychain-auth policy does not allow AgentSecrets to access this service namespace.\n" +
			"Check your keychain-auth configuration."
	case reasonTargetNotAllowed:
		return "keychain-auth policy does not allow access to this secret.\n" +
			"Check your keychain-auth configuration."
	case reasonMalformedRequest:
		return "keychain-auth received a malformed request. This is a bug — please report it."
	case reasonInternalError:
		return "keychain-auth encountered an internal error. Try restarting the daemon:\n" +
			"  keychain-auth start"
	default:
		return fmt.Sprintf("keychain-auth denied the request: %s", reason)
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
