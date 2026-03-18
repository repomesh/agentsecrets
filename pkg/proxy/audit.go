package proxy

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	_ "github.com/glebarez/go-sqlite"
)

// AuditEvent records a single proxied API call.
// Secret KEY NAMES are logged. Secret VALUES are NEVER logged.
type AuditEvent struct {
	ID             string    `json:"id"`
	Timestamp      time.Time `json:"timestamp"`
	SecretKeys     []string  `json:"secret_keys"`            // KEY NAMES e.g. ["STRIPE_SECRET_KEY"]
	AgentID        string    `json:"agent_id,omitempty"`     // from agent identification
	IdentityLevel  string    `json:"identity_level"`         // "anonymous", "declared", "issued"
	Method         string    `json:"method"`
	TargetURL      string    `json:"target_url"`
	Domain         string    `json:"domain,omitempty"`       // Target domain (e.g. "api.stripe.com")
	AuthStyles     []string  `json:"auth_styles"`            // e.g. ["bearer"]
	StatusCode     int       `json:"status_code"`
	DurationMs     int64     `json:"duration_ms"`
	Status         string    `json:"status"`                 // "OK" or "BLOCKED"
	Reason         string    `json:"reason,omitempty"`       // "domain_not_in_allowlist" or "-"
	Redacted       bool      `json:"redacted"`
	ResolutionPath string    `json:"resolution_path"`        // e.g. "local proxy", "cloud"
	CallerRole     string    `json:"caller_role,omitempty"`  // e.g. "member"
	WorkspaceID    string    `json:"workspace_id,omitempty"`
	ProjectID      string    `json:"project_id,omitempty"`
	TokenID        string    `json:"token_id,omitempty"`
}

// AuditLogger writes AuditEvents to a local SQLite database.
type AuditLogger struct {
	db *sql.DB
	mu sync.Mutex
}

// DefaultLogPath returns the default audit database path: ~/.agentsecrets/audit.db
func DefaultLogPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cannot determine home directory: %w", err)
	}
	dir := filepath.Join(home, ".agentsecrets")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", fmt.Errorf("cannot create config directory: %w", err)
	}
	return filepath.Join(dir, "audit.db"), nil
}

// NewAuditLogger creates an audit logger that connects to a local SQLite database.
func NewAuditLogger(dbPath string) (*AuditLogger, error) {
	if dbPath == "" {
		var err error
		dbPath, err = DefaultLogPath()
		if err != nil {
			return nil, err
		}
	}

	// Connect to SQLite
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open sqlite database: %w", err)
	}

	// Create table if it doesn't exist
	schema := `
	CREATE TABLE IF NOT EXISTS audit_events (
		id TEXT PRIMARY KEY,
		timestamp DATETIME NOT NULL,
		agent_id TEXT,
		identity_level TEXT,
		method TEXT,
		target_url TEXT,
		domain TEXT,
		status_code INTEGER,
		duration_ms INTEGER,
		status TEXT,
		reason TEXT,
		redacted BOOLEAN,
		resolution_path TEXT,
		caller_role TEXT,
		workspace_id TEXT,
		project_id TEXT,
		token_id TEXT,
		secret_keys TEXT,
		auth_styles TEXT
	);
	CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_events(timestamp);
	CREATE INDEX IF NOT EXISTS idx_audit_agent ON audit_events(agent_id);
	CREATE INDEX IF NOT EXISTS idx_audit_domain ON audit_events(domain);
	`
	if _, err := db.Exec(schema); err != nil {
		return nil, fmt.Errorf("failed to initialize schema: %w", err)
	}

	return &AuditLogger{db: db}, nil
}

// Log writes a single audit event to the SQLite database.
func (a *AuditLogger) Log(event AuditEvent) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if event.ID == "" {
		event.ID = "log_" + strings.ReplaceAll(uuid.New().String(), "-", "")
	}

	keysJSON, _ := json.Marshal(event.SecretKeys)
	stylesJSON, _ := json.Marshal(event.AuthStyles)

	query := `
	INSERT INTO audit_events (
		id, timestamp, agent_id, identity_level, method, target_url, 
		domain, status_code, duration_ms, status, reason, redacted, 
		resolution_path, caller_role, workspace_id, project_id, token_id, 
		secret_keys, auth_styles
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	_, err := a.db.ExecContext(context.Background(), query,
		event.ID,
		event.Timestamp.UTC(), // Important standard for SQLite
		event.AgentID,
		event.IdentityLevel,
		event.Method,
		event.TargetURL,
		event.Domain,
		event.StatusCode,
		event.DurationMs,
		event.Status,
		event.Reason,
		event.Redacted,
		event.ResolutionPath,
		event.CallerRole,
		event.WorkspaceID,
		event.ProjectID,
		event.TokenID,
		string(keysJSON),
		string(stylesJSON),
	)

	return err
}

// Close closes the underlying database connection.
func (a *AuditLogger) Close() error {
	if a.db != nil {
		return a.db.Close()
	}
	return nil
}

// DB returns the underlying database for querying.
func (a *AuditLogger) DB() *sql.DB {
	return a.db
}
