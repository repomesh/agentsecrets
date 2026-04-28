package keychainauth

// defaultSocketPath is the hardcoded Unix socket path for keychain-auth.
//
// This is intentionally NOT configurable. The integration spec (§7) explicitly
// prohibits making the socket path configurable in v1 because configuration
// introduces surface area for misconfiguration attacks. A compromised config
// could redirect AgentSecrets to a rogue socket that impersonates keychain-auth.
//
// Both platforms use the same path. This matches keychain-auth's
// internal/config/paths_linux.go and paths_darwin.go DefaultSocketPath().
const defaultSocketPath = "/var/run/keychain-auth/agent.sock"

// SocketPath returns the keychain-auth Unix socket path.
func SocketPath() string {
	return defaultSocketPath
}
