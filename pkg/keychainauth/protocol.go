// Package keychainauth is the client-side integration with the keychain-auth daemon.
//
// keychain-auth is a standalone security daemon that mediates all secret reads
// between AgentSecrets and the OS keychain. It verifies process identity (binary
// hash + PID) before granting access, and enforces namespace isolation so only
// secrets in the {project_id}:{environment}:{key} format are readable.
//
// This package owns:
//   - The Unix socket session lifecycle (init, request, close)
//   - Auto-setup of keychain-auth (install, register, start)
//   - User-facing error messages for rejection/denial
//
// This package does NOT own:
//   - Writing secrets to the OS keychain (pkg/keyring handles that)
//   - keychain-auth's internal verification logic
//   - The daemon process itself
package keychainauth

// --- Wire protocol types ---
// These mirror github.com/The-17/keychain-auth/internal/protocol/messages.go.
// Duplicated intentionally — the two codebases are decoupled by design.

// MessageType enumerates all valid protocol message types.
type messageType string

const (
	typeSessionInit     messageType = "SESSION_INIT"
	typeSessionAccepted messageType = "SESSION_ACCEPTED"
	typeSessionRejected messageType = "SESSION_REJECTED"
	typeSecretRequest   messageType = "SECRET_REQUEST"
	typeSecretResponse  messageType = "SECRET_RESPONSE"
	typeSecretDenied    messageType = "SECRET_DENIED"
)

// rejectReason enumerates all valid rejection/denial reason codes.
type rejectReason string

const (
	reasonHashMismatch        rejectReason = "HASH_MISMATCH"
	reasonInvalidPID          rejectReason = "INVALID_PID"
	reasonPathMismatch        rejectReason = "PATH_MISMATCH"
	reasonUnsupportedProtocol rejectReason = "UNSUPPORTED_PROTOCOL"
	reasonUnknownSession      rejectReason = "UNKNOWN_SESSION"
	reasonSessionExpired      rejectReason = "SESSION_EXPIRED"
	reasonSessionInvalidated  rejectReason = "SESSION_INVALIDATED"
	reasonSecretNotFound      rejectReason = "SECRET_NOT_FOUND"
	reasonInvalidKey          rejectReason = "INVALID_KEY"
)

// --- Inbound messages (AgentSecrets → keychain-auth) ---

type sessionInitMsg struct {
	Type            messageType `json:"type"`
	PID             int         `json:"pid"`
	BinaryPath      string      `json:"binary_path"`
	BinaryHash      string      `json:"binary_hash"`
	ProtocolVersion string      `json:"protocol_version"`
}

type secretRequestMsg struct {
	Type         messageType `json:"type"`
	SessionToken string      `json:"session_token"`
	ProjectID    string      `json:"project_id"`
	Environment  string      `json:"environment"`
	Key          string      `json:"key"`
}

// --- Outbound messages (keychain-auth → AgentSecrets) ---

type envelope struct {
	Type messageType `json:"type"`
}

type sessionAcceptedMsg struct {
	Type         messageType `json:"type"`
	SessionToken string      `json:"session_token"`
}

type sessionRejectedMsg struct {
	Type   messageType  `json:"type"`
	Reason rejectReason `json:"reason"`
}

type secretResponseMsg struct {
	Type  messageType `json:"type"`
	Key   string      `json:"key"`
	Value string      `json:"value"`
}

type secretDeniedMsg struct {
	Type   messageType  `json:"type"`
	Key    string       `json:"key"`
	Reason rejectReason `json:"reason"`
}
