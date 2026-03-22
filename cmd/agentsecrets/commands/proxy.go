package commands

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/The-17/agentsecrets/pkg/config"
	"github.com/The-17/agentsecrets/pkg/log"
	"github.com/The-17/agentsecrets/pkg/proxy"
	"github.com/The-17/agentsecrets/pkg/ui"
)

var (
	proxyPort      int
	logsSecretFlag string
	logsLastFlag   int
	logsEnvFlag    string
)

var proxyCmd = &cobra.Command{
	Use:   "proxy",
	Short: "Manage the AgentSecrets credentialed proxy",
	Long:  `Start, stop, and monitor the HTTP proxy that lets AI agents make authenticated API calls without seeing credential values.`,
}

var proxyStartCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the proxy server",
	Long:  `Start the HTTP proxy on localhost. AI agents send requests here with X-AS-* headers; the proxy injects real credentials and forwards to the target API.`,
	RunE:  runProxyStart,
}

var proxyStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Check if the proxy is running",
	RunE:  runProxyStatus,
}

var proxyStopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Stop the running proxy server",
	RunE:  runProxyStop,
}

var proxySyncCmd = &cobra.Command{
	Use:   "sync",
	Short: "Force an immediate revocation list sync",
	RunE:  runProxySync,
}

var proxyLogsCmd = &cobra.Command{
	Use:   "logs",
	Short: "View proxy audit log",
	Long:  `View the audit log of API calls made through the proxy. Shows secret key names, target URLs, and response codes. Never shows secret values.`,
	RunE:  runProxyLogs,
}

func init() {
	proxyStartCmd.Flags().IntVar(&proxyPort, "port", 8765, "Port to listen on")

	proxyLogsCmd.Flags().StringVar(&logsSecretFlag, "secret", "", "Filter logs by secret key name")
	proxyLogsCmd.Flags().IntVar(&logsLastFlag, "last", 20, "Number of recent log entries to show")
	proxyLogsCmd.Flags().StringVar(&logsEnvFlag, "env", "", "Filter logs by environment (development, staging, production)")

	proxyCmd.AddCommand(proxyStartCmd)
	proxyCmd.AddCommand(proxyStatusCmd)
	proxyCmd.AddCommand(proxyStopCmd)
	proxyCmd.AddCommand(proxySyncCmd)
	proxyCmd.AddCommand(proxyLogsCmd)
}

// pidFilePath returns the path to the proxy PID file (~/.agentsecrets/proxy.pid).
func pidFilePath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cannot determine home directory: %w", err)
	}
	return filepath.Join(home, ".agentsecrets", "proxy.pid"), nil
}

// writePIDFile writes the current PID and start time to the PID file.
func writePIDFile(port int) error {
	path, err := pidFilePath()
	if err != nil {
		return err
	}
	data := fmt.Sprintf("%d\n%d\n%d", os.Getpid(), time.Now().Unix(), port)
	return os.WriteFile(path, []byte(data), 0600)
}

// removePIDFile cleans up the PID file on shutdown.
func removePIDFile() {
	path, err := pidFilePath()
	if err != nil {
		return
	}
	os.Remove(path)
}

// readPIDFile reads the PID, start time, and port from the PID file.
func readPIDFile() (pid int, startTime time.Time, port int, err error) {
	path, err := pidFilePath()
	if err != nil {
		return 0, time.Time{}, 0, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, time.Time{}, 0, err
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) < 3 {
		return 0, time.Time{}, 0, fmt.Errorf("invalid PID file format")
	}
	pid, err = strconv.Atoi(lines[0])
	if err != nil {
		return 0, time.Time{}, 0, fmt.Errorf("invalid PID: %w", err)
	}
	ts, err := strconv.ParseInt(lines[1], 10, 64)
	if err != nil {
		return 0, time.Time{}, 0, fmt.Errorf("invalid timestamp: %w", err)
	}
	port, err = strconv.Atoi(lines[2])
	if err != nil {
		return 0, time.Time{}, 0, fmt.Errorf("invalid port: %w", err)
	}
	return pid, time.Unix(ts, 0), port, nil
}

// isProcessAlive checks if a process with the given PID is running.
func isProcessAlive(pid int) bool {
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	// On Unix, FindProcess always succeeds; send signal 0 to probe.
	err = p.Signal(syscall.Signal(0))
	return err == nil
}

// formatUptime returns a human-readable uptime string from a start time.
func formatUptime(start time.Time) string {
	d := time.Since(start)
	hours := int(d.Hours())
	minutes := int(d.Minutes()) % 60

	if hours > 0 {
		return fmt.Sprintf("%dh %dm", hours, minutes)
	}
	if minutes > 0 {
		return fmt.Sprintf("%dm %ds", minutes, int(d.Seconds())%60)
	}
	return fmt.Sprintf("%ds", int(d.Seconds()))
}

func runProxyStart(cmd *cobra.Command, args []string) error {
	fmt.Println()
	ui.Banner("AgentSecrets Proxy")
	ui.Divider()

	// Load project context
	project, err := config.LoadProjectConfig()
	if err != nil || project.ProjectID == "" {
		ui.Error("No project found. Run 'agentsecrets project use <name>' first.")
		return nil
	}

	ui.StatusRow("Project:", project.ProjectName)
	ui.StatusRow("Port:", fmt.Sprintf("%d", proxyPort))
	fmt.Println()

	engine, err := proxy.NewEngine(project.ProjectID)
	if err != nil {
		ui.Error(fmt.Sprintf("Failed to initialize proxy engine: %v", err))
		return nil
	}

	agentToken := os.Getenv("AS_AGENT_TOKEN")
	if agentToken != "" {
		ui.StatusRow("Agent:", "Token provided via AS_AGENT_TOKEN (issued)")
	} else {
		ui.StatusRowDim("Agent:", "(none — calls will be logged as anonymous)")
	}

	server := proxy.NewServer(proxyPort, engine)

	// Write PID file for proxy status
	if err := writePIDFile(proxyPort); err != nil {
		ui.Warning(fmt.Sprintf("Failed to write PID file: %v", err))
	}
	defer removePIDFile()

	ui.Success(fmt.Sprintf("\nProxy listening on http://localhost:%d/proxy", proxyPort))
	ui.Info("Press Ctrl+C to stop")
	fmt.Println()

	return server.Start()
}

func runProxyStatus(cmd *cobra.Command, args []string) error {
	fmt.Println()
	ui.Banner("Proxy Status")
	ui.Divider()

	// Read PID file for running state
	pid, startTime, port, err := readPIDFile()
	if err != nil {
		ui.StatusRow("Proxy status:", ui.ErrorStyle.Render("not running"))
	} else if !isProcessAlive(pid) {
		ui.StatusRow("Proxy status:", ui.ErrorStyle.Render("not running"))
		ui.StatusRowDim("Last PID:", fmt.Sprintf("%d (exited)", pid))
		removePIDFile()
	} else {
		ui.StatusRow("Proxy status:", ui.SuccessStyle.Render("running"))
		ui.StatusRow("PID:", fmt.Sprintf("%d", pid))
		ui.StatusRow("Port:", fmt.Sprintf("%d", port))
		ui.StatusRow("Uptime:", formatUptime(startTime))

		// Try to fetch live metrics from /health
		healthURL := fmt.Sprintf("http://localhost:%d/health", port)
		client := &http.Client{Timeout: 1 * time.Second}
		resp, err := client.Get(healthURL)
		if err == nil {
			defer resp.Body.Close()
			var health struct {
				LastSync     string   `json:"last_sync"`
				RevokedCount int      `json:"revoked_count"`
				RevokedIDs   []string `json:"revoked_ids"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&health); err == nil {
				syncVal := "never"
				if t, err := time.Parse(time.RFC3339, health.LastSync); err == nil && !t.IsZero() {
					syncVal = formatUptime(t) + " ago"
				}
				ui.StatusRow("Last sync:", syncVal)
				if health.RevokedCount > 0 {
					ui.StatusRow("Revoked IDs:", fmt.Sprintf("%d (%s)", health.RevokedCount, strings.Join(health.RevokedIDs, ", ")))
				} else {
					ui.StatusRow("Revoked IDs:", "0")
				}
			} else {
				ui.StatusRowDim("Last sync:", "(failed to parse health data)")
				ui.StatusRowDim("Revoked IDs:", "(failed to parse health data)")
			}
		} else {
			ui.StatusRowDim("Last sync:", "(proxy unreachable for status check)")
			ui.StatusRowDim("Revoked IDs:", "(proxy unreachable for status check)")
		}
	}

	fmt.Println()

	// Check the audit database file
	logPath, err := proxy.DefaultLogPath()
	if err != nil {
		ui.StatusRowDim("Audit DB:", "Not found")
	} else {
		info, err := os.Stat(logPath)
		if err != nil {
			ui.StatusRowDim("Audit DB:", "No audit database yet")
		} else {
			ui.StatusRow("Audit DB:", logPath)
			ui.StatusRow("Size:", fmt.Sprintf("%d bytes", info.Size()))
			ui.StatusRow("Last modified:", info.ModTime().Format(time.RFC3339))
		}
	}

	fmt.Println()
	ui.Info("To start the proxy: agentsecrets proxy start")
	fmt.Println()
	return nil
}

func runProxyStop(cmd *cobra.Command, args []string) error {
	pid, _, _, err := readPIDFile()
	if err != nil {
		ui.Info("No running proxy found (no PID file).")
		return nil
	}

	if !isProcessAlive(pid) {
		ui.Info(fmt.Sprintf("Proxy process %d is already dead.", pid))
		removePIDFile()
		return nil
	}

	ui.Info(fmt.Sprintf("Stopping proxy (PID %d)...", pid))
	p, _ := os.FindProcess(pid)
	if err := p.Signal(syscall.SIGTERM); err != nil {
		return fmt.Errorf("failed to send SIGTERM to proxy: %w", err)
	}

	// Wait up to 5 seconds for it to stop
	for i := 0; i < 50; i++ {
		if !isProcessAlive(pid) {
			removePIDFile()
			ui.Success("Proxy stopped.")
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}

	// Try SIGKILL if still alive
	ui.Warning("Proxy didn't stop with SIGTERM, sending SIGKILL...")
	if err := p.Kill(); err != nil {
		return fmt.Errorf("failed to kill proxy: %w", err)
	}
	removePIDFile()
	ui.Success("Proxy force-killed.")
	return nil
}

func runProxySync(cmd *cobra.Command, args []string) error {
	// Determine port from PID file or default
	port := 8765
	_, _, pidPort, err := readPIDFile()
	if err == nil && pidPort > 0 {
		port = pidPort
	}

	url := fmt.Sprintf("http://localhost:%d/sync", port)
	client := &http.Client{Timeout: 5 * time.Second}

	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("proxy not reachable on port %d: %w", port, err)
	}
	defer resp.Body.Close()

	var result map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("invalid response from proxy: %w", err)
	}

	if result["status"] == "ok" {
		ui.Success("Revocation sync triggered successfully.")
	} else {
		ui.Warning("Sync request returned unexpected status.")
	}
	return nil
}

func runProxyLogs(cmd *cobra.Command, args []string) error {
	fmt.Println()
	ui.Banner("Proxy Audit Log")

	// Query the SQLite audit database
	svc, err := log.NewService(nil, nil)
	if err != nil {
		ui.Info("No audit log found. The proxy hasn't been used yet.")
		fmt.Println()
		return nil
	}
	defer svc.Close()

	filter := log.Filter{
		Limit: logsLastFlag,
	}
	if logsSecretFlag != "" {
		filter.Credential = logsSecretFlag
	}

	events, err := svc.QueryLocal(filter)
	if err != nil {
		return fmt.Errorf("failed to query audit log: %w", err)
	}

	if len(events) == 0 {
		if logsSecretFlag != "" {
			ui.Info(fmt.Sprintf("No log entries found for secret %q", logsSecretFlag))
		} else {
			ui.Info("No log entries found. The proxy hasn't been used yet.")
		}
		fmt.Println()
		return nil
	}

	// Display as table (events come back newest-first from QueryLocal)
	headers := []string{"Time", "Status", "Method", "Target URL", "Secrets", "Auth", "Code", "Reason", "Duration"}
	rows := make([][]string, len(events))
	for i, e := range events {
		targetURL := e.TargetURL
		targetURL = strings.TrimPrefix(targetURL, "https://")
		targetURL = strings.TrimPrefix(targetURL, "http://")
		if len(targetURL) > 30 {
			targetURL = targetURL[:27] + "..."
		}
		
		statusStr := e.Status
		if statusStr == "BLOCKED" {
			statusStr = ui.ErrorStyle.Render("x BLOCK")
		} else if statusStr == "OK" {
			statusStr = ui.SuccessStyle.Render("* OK")
		} else {
			statusStr = "* OK" // backward compat for old logs
		}

		reasonStr := e.Reason
		if reasonStr == "" {
			reasonStr = "-"
		}
		if e.Redacted {
			statusStr += " " + ui.ErrorStyle.Render("(REDACTED)")
		}

		rows[i] = []string{
			e.Timestamp.Format("15:04:05"),
			statusStr,
			e.Method,
			targetURL,
			strings.Join(e.SecretKeys, ", "),
			strings.Join(e.AuthStyles, ", "),
			fmt.Sprintf("%d", e.StatusCode),
			reasonStr,
			fmt.Sprintf("%dms", e.DurationMs),
		}
	}

	table := ui.RenderTable(headers, rows)
	fmt.Printf("%s\n", table)

	ui.Info(fmt.Sprintf("Showing %d entries", len(events)))
	fmt.Println()
	return nil
}
