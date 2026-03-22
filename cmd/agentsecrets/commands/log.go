package commands

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/The-17/agentsecrets/pkg/log"
	"github.com/The-17/agentsecrets/pkg/proxy"
	"github.com/The-17/agentsecrets/pkg/ui"
	"github.com/spf13/cobra"
)

var (
	logService  *log.Service
	logPageSize = 20
)

var logWatchCmd = &cobra.Command{
	Use:   "watch",
	Short: "Live stream new audit log entries",
	RunE: func(cmd *cobra.Command, args []string) error {
		return watchLogs(logService)
	},
}

var logCmd = &cobra.Command{
	Use:   "log",
	Short: "View and filter the credential call audit log",
	Long:  "Every call made through the AgentSecrets proxy is logged here.\nThe log records which agent made the call, which credential was\nreferenced, which API was called, and what happened — but never\nthe credential value.",
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		// Run root's persistent pre-run if exists (or init auth)
		if err := authService.EnsureAuth(cmd, args); err != nil {
			return err
		}
		var err error
		logService, err = log.NewService(apiClient, nil)
		if err != nil {
			return fmt.Errorf("could not initialize log service: %v", err)
		}
		return nil
	},
	RunE: runLogList,
}

var logShowCmd = &cobra.Command{
	Use:   "show <log_id>",
	Short: "Show a single entry in full",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		id := args[0]
		entry, err := logService.GetLog(id)
		if err != nil {
			return err
		}

		fmt.Println("─────────────────────────────────────────────────────────")
		fmt.Printf("LOG ENTRY  %s\n", entry.ID)
		fmt.Println("─────────────────────────────────────────────────────────")
		fmt.Printf("Timestamp        %s\n\n", entry.Timestamp.Format("2006-01-02 15:04:05.000 MST"))
		
		ws := entry.WorkspaceID
		if ws == "" { ws = "(none)" }
		pr := entry.ProjectID
		if pr == "" { pr = "(none)" }

		fmt.Printf("Workspace        %s\n", ws)
		fmt.Printf("Project          %s\n\n", pr)

		agent := entry.AgentID
		if agent == "" { agent = "(none)" }
		
		fmt.Printf("Agent            %s\n", agent)
		fmt.Printf("Token            %s\n", entry.TokenID)
		fmt.Printf("Environment      %s\n", entry.Environment)
		fmt.Printf("Identity level   %s\n\n", entry.IdentityLevel)
		
		fmt.Printf("Credential       %s\n", strings.Join(entry.SecretKeys, ", "))
		fmt.Printf("Injection        %s\n\n", strings.Join(entry.AuthStyles, ", "))

		fmt.Printf("Target           %s %s\n", strings.ToUpper(entry.Method), entry.TargetURL)
		fmt.Printf("Domain           %s\n\n", entry.Domain)

		statusText := fmt.Sprintf("%d", entry.StatusCode)
		if entry.Status == "BLOCKED" {
			statusText = "BLOCKED (" + entry.Reason + ")"
		}

		fmt.Printf("Status           %s\n", statusText)
		fmt.Printf("Duration         %dms\n", entry.DurationMs)
		redactedStr := "no"
		if entry.Redacted { redactedStr = "yes" }
		fmt.Printf("Redacted         %s\n", redactedStr)
		fmt.Printf("Resolution       %s\n\n", entry.ResolutionPath)
		fmt.Printf("Caller role      %s\n", entry.CallerRole)
		fmt.Println("─────────────────────────────────────────────────────────")
		return nil
	},
}

var logSummaryCmd = &cobra.Command{
	Use:   "summary",
	Short: "Aggregate statistics",
	RunE: func(cmd *cobra.Command, args []string) error {
		since, _ := cmd.Flags().GetString("since")
		filter := buildFilter(cmd, since)
		
		logs, err := logService.QueryLocal(filter)
		if err != nil {
			return err
		}

		total := len(logs)
		if total == 0 {
			fmt.Println("No logs found for the given criteria.")
			return nil
		}

		succeeded := 0
		failed := 0
		redacted := 0
		identities := map[string]int{"issued": 0, "declared": 0, "anonymous": 0}
		agentCounts := make(map[string]int)
		agentFailed := make(map[string]int)
		credCounts := make(map[string]int)
		domainCounts := make(map[string]int)

		for _, l := range logs {
			isFailed := l.StatusCode >= 400 || l.Status == "BLOCKED"
			if isFailed {
				failed++
			} else {
				succeeded++
			}
			if l.Redacted {
				redacted++
			}
			level := l.IdentityLevel
			if level == "" { level = "anonymous" }
			identities[level]++

			ag := l.AgentID
			if ag == "" { ag = "(anonymous)" }
			agentCounts[ag]++
			if isFailed {
				agentFailed[ag]++
			}

			for _, key := range l.SecretKeys {
				credCounts[key]++
			}

			if l.Domain != "" {
				domainCounts[l.Domain]++
			}
		}

		fmt.Println("LOG SUMMARY")
		fmt.Println("────────────────────────────────────────────────────")
		fmt.Printf("Total calls       %d\n", total)
		fmt.Printf("  Succeeded       %d  (%.1f%%)\n", succeeded, float64(succeeded)/float64(total)*100)
		fmt.Printf("  Failed          %d  (%.1f%%)\n", failed, float64(failed)/float64(total)*100)
		fmt.Printf("  Redacted        %d\n\n", redacted)

		fmt.Println("By identity level")
		fmt.Printf("  Issued          %d\n", identities["issued"])
		fmt.Printf("  Declared        %d\n", identities["declared"])
		fmt.Printf("  Anonymous       %d\n", identities["anonymous"])

		// By agent breakdown
		fmt.Println("\nBy agent")
		printTopN(agentCounts, agentFailed, 5)

		// By credential breakdown
		fmt.Println("\nBy credential")
		printTopN(credCounts, nil, 5)

		// By domain breakdown
		fmt.Println("\nBy domain")
		printTopN(domainCounts, nil, 5)

		if identities["anonymous"] > 0 {
			fmt.Println("\n" + ui.WarningStyle.Render(fmt.Sprintf("%d anonymous calls detected.", identities["anonymous"])))
			fmt.Println("Run: agentsecrets log --identity anonymous")
			fmt.Println("to identify which tools are missing agent identity.")
		}

		return nil
	},
}

// logExportCmd exports audit logs in JSONL or CSV format.
var logExportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export audit log entries",
	Long:  "Export audit log entries to a file in JSONL or CSV format.\nThe --since flag is required to scope the export.",
	RunE: func(cmd *cobra.Command, args []string) error {
		sinceStr, _ := cmd.Flags().GetString("since")
		if sinceStr == "" {
			return fmt.Errorf("--since is required for export (e.g. --since 7d)")
		}

		untilStr, _ := cmd.Flags().GetString("until")
		format, _ := cmd.Flags().GetString("format")
		output, _ := cmd.Flags().GetString("output")
		agent, _ := cmd.Flags().GetString("agent")
		credential, _ := cmd.Flags().GetString("credential")

		filter := log.Filter{
			Agent:      agent,
			Credential: credential,
			Limit:      0, // no limit for export
		}
		if sinceStr != "" {
			filter.Since = parseDuration(sinceStr)
		}
		if untilStr != "" {
			filter.Until = parseDuration(untilStr)
		}

		logs, err := logService.QueryLocal(filter)
		if err != nil {
			return err
		}

		if len(logs) == 0 {
			fmt.Println(ui.DimStyle.Render("No log entries match your criteria."))
			return nil
		}

		// Determine output writer
		var writer *os.File
		if output != "" && output != "-" {
			writer, err = os.Create(output)
			if err != nil {
				return fmt.Errorf("failed to create output file: %w", err)
			}
			defer writer.Close()
		} else {
			writer = os.Stdout
		}

		switch format {
		case "csv":
			return exportCSV(writer, logs)
		default:
			return exportJSONL(writer, logs)
		}
	},
}

func exportJSONL(writer *os.File, logs []proxy.AuditEvent) error {
	enc := json.NewEncoder(writer)
	for i, l := range logs {
		if err := enc.Encode(l); err != nil {
			return fmt.Errorf("failed to encode log entry: %w", err)
		}
		if i > 0 && i%100 == 0 {
			fmt.Fprintf(os.Stderr, "\rExported %d / %d entries...", i, len(logs))
		}
	}
	if len(logs) > 100 {
		fmt.Fprintf(os.Stderr, "\rExported %d / %d entries... done.\n", len(logs), len(logs))
	}
	return nil
}

func exportCSV(writer *os.File, logs []proxy.AuditEvent) error {
	w := csv.NewWriter(writer)
	defer w.Flush()

	// Write headers
	headers := []string{"id", "timestamp", "environment", "agent_id", "identity_level", "method", "target_url", "domain", "status_code", "duration_ms", "status", "reason", "redacted", "secret_keys", "auth_styles"}
	if err := w.Write(headers); err != nil {
		return fmt.Errorf("failed to write CSV headers: %w", err)
	}

	for i, l := range logs {
		redacted := "false"
		if l.Redacted {
			redacted = "true"
		}
		row := []string{
			l.ID,
			l.Timestamp.Format(time.RFC3339),
			l.Environment,
			l.AgentID,
			l.IdentityLevel,
			l.Method,
			l.TargetURL,
			l.Domain,
			fmt.Sprintf("%d", l.StatusCode),
			fmt.Sprintf("%d", l.DurationMs),
			l.Status,
			l.Reason,
			redacted,
			strings.Join(l.SecretKeys, ";"),
			strings.Join(l.AuthStyles, ";"),
		}
		if err := w.Write(row); err != nil {
			return fmt.Errorf("failed to write CSV row: %w", err)
		}
		if i > 0 && i%100 == 0 {
			fmt.Fprintf(os.Stderr, "\rExported %d / %d entries...", i, len(logs))
		}
	}
	if len(logs) > 100 {
		fmt.Fprintf(os.Stderr, "\rExported %d / %d entries... done.\n", len(logs), len(logs))
	}
	return nil
}

// printTopN prints the top N entries from a counts map, with optional failure counts.
// Pass nil for failedCounts when failure breakdown is not needed.
func printTopN(counts map[string]int, failedCounts map[string]int, n int) {
	type entry struct {
		name  string
		count int
	}
	entries := make([]entry, 0, len(counts))
	for name, count := range counts {
		entries = append(entries, entry{name, count})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].count > entries[j].count })

	for i, e := range entries {
		if i >= n {
			break
		}
		if failedCounts != nil {
			if failed := failedCounts[e.name]; failed > 0 {
				fmt.Printf("  %-18s %d  (%d failed)\n", e.name, e.count, failed)
				continue
			}
		}
		fmt.Printf("  %-18s %d\n", e.name, e.count)
	}
}

func parseDuration(s string) time.Time {
	if s == "" { return time.Time{} }
	if strings.HasSuffix(s, "d") {
		days := 0
		fmt.Sscanf(s, "%dd", &days)
		return time.Now().AddDate(0, 0, -days)
	}
	d, err := time.ParseDuration(s)
	if err == nil {
		return time.Now().Add(-d)
	}
	t, err := time.Parse("2006-01-02", s)
	if err == nil {
		return t
	}
	return time.Time{}
}

func buildFilter(cmd *cobra.Command, sinceStr string) log.Filter {
	f := log.Filter{}
	f.Agent, _ = cmd.Flags().GetString("agent")
	f.Token, _ = cmd.Flags().GetString("token")
	f.Identity, _ = cmd.Flags().GetString("identity")
	f.Credential, _ = cmd.Flags().GetString("credential")
	f.Domain, _ = cmd.Flags().GetString("domain")
	f.Method, _ = cmd.Flags().GetString("method")
	f.Status, _ = cmd.Flags().GetInt("status")
	f.StatusClass, _ = cmd.Flags().GetString("status-class")
	f.Failed, _ = cmd.Flags().GetBool("failed")
	f.Blocked, _ = cmd.Flags().GetBool("blocked")
	f.Redacted, _ = cmd.Flags().GetBool("redacted")
	f.ProjectID, _ = cmd.Flags().GetString("project")
	f.Environment, _ = cmd.Flags().GetString("env")
	f.Limit, _ = cmd.Flags().GetInt("limit")

	untilStr, _ := cmd.Flags().GetString("until")
	if sinceStr != "" { f.Since = parseDuration(sinceStr) }
	if untilStr != "" { f.Until = parseDuration(untilStr) }

	return f
}

// colorStatus returns a color-coded status string based on the HTTP status code.
func colorStatus(statusCode int, status string) string {
	if status == "BLOCKED" {
		return ui.ErrorStyle.Render("BLOCKED")
	}
	s := fmt.Sprintf("%d", statusCode)
	switch {
	case statusCode >= 200 && statusCode < 300:
		return ui.SuccessStyle.Render(s)
	case statusCode >= 300 && statusCode < 500:
		return ui.WarningStyle.Render(s)
	case statusCode >= 500:
		return ui.ErrorStyle.Render(s)
	default:
		return s
	}
}

func runLogList(cmd *cobra.Command, args []string) error {
	sinceStr, _ := cmd.Flags().GetString("since")
	filter := buildFilter(cmd, sinceStr)
	useJSON, _ := cmd.Flags().GetBool("json")
	useTail, _ := cmd.Flags().GetBool("tail")

	if useTail {
		return watchLogs(logService)
	}

	if useJSON {
		logs, err := logService.QueryLocal(filter)
		if err != nil {
			return err
		}
		enc := json.NewEncoder(os.Stdout)
		for _, l := range logs {
			enc.Encode(l)
		}
		return nil
	}

	offset := 0
	for {
		filter.Limit = logPageSize
		filter.Offset = offset
		logs, err := logService.QueryLocal(filter)
		if err != nil {
			return err
		}

		if len(logs) == 0 && offset == 0 {
			fmt.Println(ui.DimStyle.Render("No log entries match your criteria."))
			return nil
		}

		fmt.Print("\033[H\033[2J") 
		ui.Banner("Audit Log")
		fmt.Printf("Showing page %d (entries %d-%d)\n\n", (offset/logPageSize)+1, offset+1, offset+len(logs))

		headers := []string{"#", "TIME", "ENV", "AGENT", "IDENTITY", "CREDENTIAL", "DOMAIN", "STATUS", "DUR"}
		rows := [][]string{}

		anonymousCount := 0
		for i, l := range logs {
			idx := fmt.Sprintf("%d", i+1)
			t := l.Timestamp.Format("15:04:05")
			ag := l.AgentID
			if ag == "" { ag = "(anon)" }
			ident := l.IdentityLevel
			if ident == "" { ident = "anonymous" }
			
			if ident == "anonymous" {
				anonymousCount++
			}

			cred := "(none)"
			if len(l.SecretKeys) > 0 {
				cred = l.SecretKeys[0]
				if len(l.SecretKeys) > 1 {
					cred = fmt.Sprintf("%s +%d", cred, len(l.SecretKeys)-1)
				}
			}

			domain := l.Domain
			status := colorStatus(l.StatusCode, l.Status)
			dur := fmt.Sprintf("%dms", l.DurationMs)

			rows = append(rows, []string{idx, t, l.Environment, ag, ident, cred, domain, status, dur})
		}

		fmt.Println(ui.RenderTable(headers, rows))

		// Anonymous call hint
		if anonymousCount > 0 {
			fmt.Println("\n" + ui.WarningStyle.Render(fmt.Sprintf("%d anonymous calls detected.", anonymousCount)))
			fmt.Println("Run: agentsecrets log --identity anonymous")
		}

		fmt.Println("\n" + ui.DimStyle.Render("Navigation: [n]ext, [p]rev, [1-20] for detail, [q]uit"))
		fmt.Print("Action: ")
		
		var input string
		fmt.Scanln(&input)
		input = strings.ToLower(strings.TrimSpace(input))

		switch input {
		case "n":
			if len(logs) == logPageSize {
				offset += logPageSize
			}
		case "p":
			if offset >= logPageSize {
				offset -= logPageSize
			}
		case "q":
			return nil
		default:
			idx := 0
			if _, err := fmt.Sscanf(input, "%d", &idx); err == nil {
				if idx > 0 && idx <= len(logs) {
					showLogDetail(logs[idx-1])
					fmt.Println("\nPress Enter to return to list...")
					fmt.Scanln()
				}
			}
		}
	}
}

// displayLogBasic prints a single log entry in the spec format:
// 14:22:01  billing-tool  →  api.stripe.com  POST /v1/charges  200  143ms
func displayLogBasic(l proxy.AuditEvent) {
	t := l.Timestamp.Format("15:04:05")
	ag := l.AgentID
	if ag == "" { ag = "(anon)" }

	// Extract path from target URL
	path := ""
	if u, err := url.Parse(l.TargetURL); err == nil {
		path = u.Path
	}

	status := colorStatus(l.StatusCode, l.Status)
	dur := fmt.Sprintf("%dms", l.DurationMs)
	env := l.Environment
	if env == "" { env = "dev" } // fallback for display

	fmt.Printf("%s  [%s]  %s  →  %s  %s %s  %s  %s\n", t, env, ag, l.Domain, strings.ToUpper(l.Method), path, status, dur)
}

func showLogDetail(entry proxy.AuditEvent) {
	fmt.Println("\n─────────────────────────────────────────────────────────")
	fmt.Printf("LOG ENTRY  %s\n", entry.ID)
	fmt.Println("─────────────────────────────────────────────────────────")
	ui.StatusRow("Timestamp", entry.Timestamp.Format("2006-01-02 15:04:05.000 MST"))
	
	ui.StatusRow("Workspace", entry.WorkspaceID)
	ui.StatusRow("Project", entry.ProjectID)
	ui.StatusRow("Environment", entry.Environment)

	ui.StatusRow("Agent", entry.AgentID)
	ui.StatusRow("Token", entry.TokenID)
	ui.StatusRow("Identity Level", entry.IdentityLevel)
	
	ui.StatusRow("Credentials", strings.Join(entry.SecretKeys, ", "))
	ui.StatusRow("Injection", strings.Join(entry.AuthStyles, ", "))

	ui.StatusRow("Target", fmt.Sprintf("%s %s", strings.ToUpper(entry.Method), entry.TargetURL))
	ui.StatusRow("Domain", entry.Domain)

	statusText := fmt.Sprintf("%d", entry.StatusCode)
	if entry.Status == "BLOCKED" {
		statusText = "BLOCKED (" + entry.Reason + ")"
	}

	ui.StatusRow("Status", statusText)
	ui.StatusRow("Duration", fmt.Sprintf("%dms", entry.DurationMs))
	ui.StatusRow("Resolution", entry.ResolutionPath)
	ui.StatusRow("Caller Role", entry.CallerRole)
	fmt.Println("─────────────────────────────────────────────────────────")
}

func init() {
	logCmd.AddCommand(logShowCmd)
	logCmd.AddCommand(logSummaryCmd)
	logCmd.AddCommand(logWatchCmd)
	logCmd.AddCommand(logExportCmd)

	addFilterFlags := func(c *cobra.Command) {
		c.Flags().String("agent", "", "filter by agent name")
		c.Flags().String("token", "", "filter by specific token ID")
		c.Flags().String("identity", "", "filter by identity level: anonymous, declared, issued")
		c.Flags().String("credential", "", "filter by key name, e.g. STRIPE_KEY")
		c.Flags().String("domain", "", "filter by target domain")
		c.Flags().String("method", "", "filter by HTTP method")
		c.Flags().Int("status", 0, "filter by exact status code")
		c.Flags().String("status-class", "", "filter by class: 2xx, 4xx, 5xx, error")
		c.Flags().Bool("failed", false, "only show calls that failed")
		c.Flags().Bool("blocked", false, "only show calls blocked by the proxy")
		c.Flags().Bool("redacted", false, "only show calls where response was redacted")
		c.Flags().String("project", "", "filter to a specific project")
		c.Flags().String("env", "", "filter by environment (development, staging, production)")
		c.Flags().String("since", "", "e.g. 1h, 24h, 7d")
		c.Flags().String("until", "", "upper bound for time range")
		c.Flags().Int("limit", 50, "number of entries to show (default 50)")
	}

	addFilterFlags(logCmd)
	logCmd.Flags().Bool("verbose", false, "full record including allowlist snapshot")
	logCmd.Flags().Bool("json", false, "output as newline-delimited JSON")
	logCmd.Flags().Bool("csv", false, "output as CSV with headers")
	logCmd.Flags().Bool("no-color", false, "disable color output")
	logCmd.Flags().Bool("tail", false, "live stream new entries (same as log watch)")

	logSummaryCmd.Flags().String("since", "7d", "default: 7d")
	logSummaryCmd.Flags().String("until", "", "")
	logSummaryCmd.Flags().String("agent", "", "")
	logSummaryCmd.Flags().String("project", "", "")
	logSummaryCmd.Flags().String("env", "", "filter by environment")
	logSummaryCmd.Flags().Bool("json", false, "")

	// Export command flags
	logExportCmd.Flags().String("since", "", "start of time range (required, e.g. 7d, 24h, 2024-01-01)")
	logExportCmd.Flags().String("until", "", "end of time range")
	logExportCmd.Flags().String("format", "jsonl", "output format: jsonl or csv")
	logExportCmd.Flags().String("output", "", "output file path (default: stdout)")
	logExportCmd.Flags().String("agent", "", "filter by agent name")
	logExportCmd.Flags().String("credential", "", "filter by key name")
}

// watchLogs polls the local audit database for new entries and prints them as
// they appear. It runs until the process is interrupted with Ctrl+C.
func watchLogs(svc *log.Service) error {
	fmt.Println(ui.BrandStyle.Render("\nWatching audit log... (Ctrl+C to stop)"))
	fmt.Println(ui.DimStyle.Render("Press Enter to refresh manually if needed.\n"))

	lastSeen := time.Now()
	seenIDs := make(map[string]bool)

	for {
		filter := log.Filter{
			Since: lastSeen,
			Limit: 20,
		}
		logs, err := svc.QueryLocal(filter)
		if err == nil && len(logs) > 0 {
			// Logs come in newest first
			for i := len(logs) - 1; i >= 0; i-- {
				l := logs[i]
				if seenIDs[l.ID] {
					continue
				}

				displayLogBasic(l)
				seenIDs[l.ID] = true

				if l.Timestamp.After(lastSeen) {
					lastSeen = l.Timestamp
					// Clear seenIDs when timestamp advances to keep map small,
					// but keep IDs for the current lastSeen timestamp.
					for id := range seenIDs {
						delete(seenIDs, id)
					}
					seenIDs[l.ID] = true
				}
			}
		}
		time.Sleep(2 * time.Second)
	}
}
