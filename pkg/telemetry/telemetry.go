package telemetry

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/The-17/agentsecrets/pkg/api"
	"github.com/The-17/agentsecrets/pkg/config"
)

type Data struct {
	LastSync             time.Time      `json:"last_sync"`
	CommandExecutions    map[string]int `json:"command_executions"`
	CliVersion           string         `json:"cli_version,omitempty"`
	OS                   string         `json:"os,omitempty"`
	Arch                 string         `json:"arch,omitempty"`
	ActiveEnvironment    string         `json:"active_environment,omitempty"`
	ProjectSecretCount   int            `json:"project_secret_count"`
	WorkspaceType        string         `json:"workspace_type,omitempty"`
	WorkspaceMemberCount int            `json:"workspace_member_count"`
	ProxyCalls           int            `json:"proxy_calls"`
	ProxyBlocked         int            `json:"proxy_blocked"`
	ProxyRedacted        int            `json:"proxy_redacted"`
	InjectionStylesUsed  []string       `json:"injection_styles_used,omitempty"`
	IntegrationsActive   []string       `json:"integrations_active,omitempty"`
}

var (
	mu   sync.Mutex
	data *Data
)

func telemetryFilePath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, ".agentsecrets")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	return filepath.Join(dir, "telemetry.json"), nil
}

func load() error {
	path, err := telemetryFilePath()
	if err != nil {
		return err
	}

	data = &Data{
		CommandExecutions: make(map[string]int),
		LastSync:          time.Now(), // Initialize to now for new users
	}

	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // Use defaults
		}
		return err
	}

	return json.Unmarshal(b, data)
}

func save() error {
	path, err := telemetryFilePath()
	if err != nil {
		return err
	}
	b, err := json.Marshal(data)
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0600)
}

// RecordCommand increments the usage count for a CLI command.
func RecordCommand(cmdName string) {
	mu.Lock()
	defer mu.Unlock()

	if data == nil {
		_ = load()
	}

	if data.CommandExecutions == nil {
		data.CommandExecutions = make(map[string]int)
	}

	data.CommandExecutions[cmdName]++
	_ = save()
}

// RecordProxyCall increments the total proxy call counter.
func RecordProxyCall() {
	mu.Lock()
	defer mu.Unlock()
	if data == nil {
		_ = load()
	}
	data.ProxyCalls++
	_ = save()
}

// RecordProxyBlocked increments the blocked proxy request counter.
func RecordProxyBlocked() {
	mu.Lock()
	defer mu.Unlock()
	if data == nil {
		_ = load()
	}
	data.ProxyBlocked++
	_ = save()
}

// RecordProxyRedacted increments the redacted proxy response counter.
func RecordProxyRedacted() {
	mu.Lock()
	defer mu.Unlock()
	if data == nil {
		_ = load()
	}
	data.ProxyRedacted++
	_ = save()
}

// RecordInjectionStyle records a unique injection style used (e.g. "bearer", "header").
func RecordInjectionStyle(style string) {
	mu.Lock()
	defer mu.Unlock()
	if data == nil {
		_ = load()
	}
	for _, s := range data.InjectionStylesUsed {
		if s == style {
			return
		}
	}
	data.InjectionStylesUsed = append(data.InjectionStylesUsed, style)
	_ = save()
}

// RecordIntegration records a unique integration (e.g. "mcp", "env", "proxy", "exec").
func RecordIntegration(name string) {
	mu.Lock()
	defer mu.Unlock()
	if data == nil {
		_ = load()
	}
	for _, n := range data.IntegrationsActive {
		if n == name {
			return
		}
	}
	data.IntegrationsActive = append(data.IntegrationsActive, name)
	_ = save()
}

// SyncIfDue checks if 24 hours have passed and flushes telemetry to the cloud.
func SyncIfDue(client *api.Client, cliVersion string) {
	mu.Lock()
	defer mu.Unlock()

	if client == nil {
		return
	}

	if data == nil {
		_ = load()
	}

	if time.Since(data.LastSync) >= 24*time.Hour {
		if len(data.CommandExecutions) == 0 {
			data.LastSync = time.Now()
			_ = save()
			return
		}

		activeEnv := config.ResolveEnvironment()
		
		wsType := "personal"
		if gc, err := config.LoadGlobalConfig(); err == nil && gc != nil {
			if wsID := gc.SelectedWorkspaceID; wsID != "" {
				if ws, ok := gc.Workspaces[wsID]; ok && ws.Type != "" {
					wsType = ws.Type
				}
			}
		}

		injStyles := data.InjectionStylesUsed
		if injStyles == nil {
			injStyles = []string{}
		}
		integrations := data.IntegrationsActive
		if integrations == nil {
			integrations = []string{}
		}

		payload := map[string]interface{}{
			"timestamp":                time.Now().UTC().Format(time.RFC3339),
			"command_executions":       data.CommandExecutions,
			"cli_version":              cliVersion,
			"os":                       runtime.GOOS,
			"arch":                     runtime.GOARCH,
			"active_environment":       activeEnv,
			"project_secret_count":     data.ProjectSecretCount,
			"workspace_type":           wsType,
			"workspace_member_count":   data.WorkspaceMemberCount,
			"proxy_calls":              data.ProxyCalls,
			"proxy_blocked":            data.ProxyBlocked,
			"proxy_redacted":           data.ProxyRedacted,
			"injection_styles_used":    injStyles,
			"integrations_active":      integrations,
		}

		// Fire off the API call synchronously to ensure it completes before CLI exits.
		// Since this is deferred at the very end of execution, the small delay is acceptable.
		resp, err := client.Call("telemetry.sync", "POST", payload, nil, nil)
		if err == nil && resp.StatusCode >= 200 && resp.StatusCode < 300 {
			// Only reset what was successfully pushed
			data.CommandExecutions = make(map[string]int)
			data.ProxyCalls = 0
			data.ProxyBlocked = 0
			data.ProxyRedacted = 0
			data.LastSync = time.Now()
			_ = save()
		} else if err == nil && resp != nil {
			// Print the validation error to help debug the 400 Bad Request
			if decodeErr := client.DecodeError(resp); decodeErr != nil {
				fmt.Println("\n[DEBUG] Telemetry Sync Rejected by Backend:", decodeErr)
			}
		}
		if resp != nil {
			resp.Body.Close()
		}
	}
}
