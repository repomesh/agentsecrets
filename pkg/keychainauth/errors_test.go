package keychainauth

import (
	"errors"
	"strings"
	"testing"
)

func TestUserMessage_SessionRejected(t *testing.T) {
	tests := []struct {
		reason rejectReason
		want   string
	}{
		{reasonHashMismatch, "Security check failed: AgentSecrets binary has been modified. Reinstall to continue."},
		{reasonInvalidPID, "keychain-auth could not verify this process. Try again or reinstall AgentSecrets."},
		{reasonPathMismatch, "keychain-auth rejected this binary path. Ensure AgentSecrets is installed in the expected location."},
		{reasonUnsupportedProtocol, "keychain-auth version is incompatible. Run: keychain-auth upgrade"},
		{rejectReason("UNKNOWN_REASON"), "keychain-auth rejected the session: UNKNOWN_REASON"},
	}

	for _, tt := range tests {
		t.Run(string(tt.reason), func(t *testing.T) {
			err := &SessionRejectedError{Reason: tt.reason}
			got := UserMessage(err)
			if got != tt.want {
				t.Errorf("UserMessage() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestUserMessage_SecretDenied(t *testing.T) {
	tests := []struct {
		reason rejectReason
		want   string
	}{
		{reasonSecretNotFound, `Secret "MY_KEY" not found in keychain — run 'agentsecrets secrets pull' to sync from cloud`},
		{reasonSessionExpired, "Session expired — the AgentSecrets process may have been replaced. Restart and try again."},
		{reasonSessionInvalidated, "Session invalidated — the AgentSecrets binary was modified while running. Restart and try again."},
		{reasonUnknownSession, "No active keychain-auth session. This is a bug — please report it."},
		{reasonInvalidKey, `Invalid key name "MY_KEY" — key names must not contain slashes, colons, or dots`},
		{rejectReason("UNKNOWN_REASON"), `keychain-auth denied access to "MY_KEY": UNKNOWN_REASON`},
	}

	for _, tt := range tests {
		t.Run(string(tt.reason), func(t *testing.T) {
			err := &SecretDeniedError{Key: "MY_KEY", Reason: tt.reason}
			got := UserMessage(err)
			if got != tt.want {
				t.Errorf("UserMessage() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestUserMessage_DaemonNotRunning(t *testing.T) {
	err := &DaemonNotRunningError{SocketPath: "/tmp/sock", Cause: errors.New("conn refused")}
	got := UserMessage(err)
	if !strings.Contains(got, "/tmp/sock") {
		t.Errorf("Expected message to contain socket path, got: %s", got)
	}
	if !strings.Contains(got, "keychain-auth start") {
		t.Errorf("Expected message to contain start instructions, got: %s", got)
	}
}
