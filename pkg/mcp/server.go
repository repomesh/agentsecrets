// Package mcp implements a Model Context Protocol server exposing api_call and list_secrets tools for AI agents.
package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/The-17/agentsecrets/pkg/api"
	"github.com/The-17/agentsecrets/pkg/config"
	"github.com/The-17/agentsecrets/pkg/proxy"
	"github.com/The-17/agentsecrets/pkg/secrets"
	"github.com/The-17/agentsecrets/pkg/telemetry"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// NewServer creates an MCP server with api_call and list_secrets tools.
func NewServer() *server.MCPServer {
	s := server.NewMCPServer(
		"AgentSecrets",
		"1.0.0",
		server.WithToolCapabilities(false),
	)

	s.AddTool(apiCallTool(), handleAPICall)
	s.AddTool(listSecretsTool(), handleListSecrets)

	return s
}

// Serve starts the MCP server on stdio (for Claude Desktop, Cursor, etc).
func Serve() error {
	telemetry.RecordIntegration("mcp")
	s := NewServer()
	return server.ServeStdio(s)
}

// --- Tool definitions ---

func apiCallTool() mcp.Tool {
	return mcp.NewTool("api_call",
		mcp.WithDescription(
			"Make an authenticated API call. Credentials are injected from the OS keychain — "+
				"you will NEVER see the actual secret values. "+
				"Use list_secrets first to discover available key names.",
		),
		mcp.WithString("url",
			mcp.Required(),
			mcp.Description("Target API URL (e.g. https://api.stripe.com/v1/charges)"),
		),
		mcp.WithString("method",
			mcp.Description("HTTP method: GET, POST, PUT, PATCH, DELETE. Default: GET"),
		),
		mcp.WithString("body",
			mcp.Description("Request body as a JSON string"),
		),
		mcp.WithObject("headers",
			mcp.Description("Extra request headers as key-value pairs"),
		),
		mcp.WithObject("injections",
			mcp.Required(),
			mcp.Description(
				"Map of injection_spec to secret_key_name. "+
					"Specs: \"bearer\", \"basic\", \"header:X-Name\", \"query:param\", \"body:json.path\", \"form:field\". "+
					"Example: {\"bearer\": \"STRIPE_KEY\"} or {\"header:X-API-Key\": \"API_KEY\"}",
			),
		),
	)
}

func listSecretsTool() mcp.Tool {
	return mcp.NewTool("list_secrets",
		mcp.WithDescription(
			"List available secret key names in the current project. "+
				"Returns ONLY key names, never the actual values. "+
				"Use this to discover which keys are available before calling api_call.",
		),
	)
}

// --- Handlers ---

func handleAPICall(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := req.GetArguments()

	// Required: url
	url, ok := args["url"].(string)
	if !ok || url == "" {
		return mcp.NewToolResultError("missing required parameter: url"), nil
	}

	// Optional: method (default GET)
	method, _ := args["method"].(string)
	if method == "" {
		method = "GET"
	}

	// Optional: body
	var body []byte
	if bodyStr, ok := args["body"].(string); ok && bodyStr != "" {
		body = []byte(bodyStr)
	}

	// Optional: headers
	headers := make(map[string]string)
	if hdrs, ok := args["headers"].(map[string]interface{}); ok {
		for k, v := range hdrs {
			if s, ok := v.(string); ok {
				headers[k] = s
			}
		}
	}

	// Required: injections
	rawInjections, ok := args["injections"].(map[string]interface{})
	if !ok || len(rawInjections) == 0 {
		return mcp.NewToolResultError("missing required parameter: injections — provide at least one injection like {\"bearer\": \"SECRET_KEY\"}"), nil
	}

	injections, err := parseInjections(rawInjections)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("invalid injections: %v", err)), nil
	}

	// Load project config for project ID
	project, err := config.LoadProjectConfig()
	if err != nil || project.ProjectID == "" {
		return mcp.NewToolResultError("no project configured — run 'agentsecrets init' first"), nil
	}

	// Create engine
	engine, err := proxy.NewEngine(project.ProjectID)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to initialize proxy engine: %v", err)), nil
	}

	// Execute
	result, err := engine.Execute(proxy.CallRequest{
		TargetURL:  url,
		Method:     method,
		Headers:    headers,
		Body:       body,
		Injections:    injections,
		AgentID:       "mcp",
		IdentityLevel: "issued",
	})
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("API call failed: %v", err)), nil
	}

	// Format response
	response := fmt.Sprintf("HTTP %d\n\n%s", result.StatusCode, string(result.Body))
	return mcp.NewToolResultText(response), nil
}

func handleListSecrets(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	// Create API client (same pattern as CLI)
	apiClient := api.NewClient(func() string {
		return config.GetAccessToken()
	})
	svc := secrets.NewService(apiClient)

	// List keys only (no values)
	list, err := svc.List()
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to list secrets: %v", err)), nil
	}

	if len(list) == 0 {
		return mcp.NewToolResultText("No secrets found. Use 'agentsecrets secrets set KEY=VALUE' to add one."), nil
	}

	// Build response: just key names
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Found %d secret(s):\n\n", len(list)))
	for _, s := range list {
		sb.WriteString(fmt.Sprintf("  • %s\n", s.Key))
	}
	sb.WriteString("\nUse these key names in api_call's injections parameter.")

	return mcp.NewToolResultText(sb.String()), nil
}

// parseInjections converts the agent's map format into proxy.Injection structs.
//
// Supported formats:
//
//	"bearer":          "KEY"  → {Style: "bearer", SecretKey: "KEY"}
//	"basic":           "KEY"  → {Style: "basic",  SecretKey: "KEY"}
//	"header:X-Name":   "KEY"  → {Style: "header", Target: "X-Name", SecretKey: "KEY"}
//	"query:param":     "KEY"  → {Style: "query",  Target: "param",  SecretKey: "KEY"}
//	"body:path.field": "KEY"  → {Style: "body",   Target: "path.field", SecretKey: "KEY"}
//	"form:field":      "KEY"  → {Style: "form",   Target: "field",  SecretKey: "KEY"}
func parseInjections(raw map[string]interface{}) ([]proxy.Injection, error) {
	var injections []proxy.Injection

	for spec, val := range raw {
		secretKey, ok := val.(string)
		if !ok {
			return nil, fmt.Errorf("injection value for %q must be a string (secret key name)", spec)
		}

		inj := proxy.Injection{SecretKey: secretKey}

		// Parse "style" or "style:target"
		parts := strings.SplitN(spec, ":", 2)
		style := strings.ToLower(parts[0])

		switch style {
		case "bearer", "basic":
			inj.Style = style
		case "header", "query", "body", "form":
			if len(parts) != 2 || parts[1] == "" {
				return nil, fmt.Errorf("%s injection requires a target — use %q format", style, style+":target_name")
			}
			inj.Style = style
			inj.Target = parts[1]
		default:
			validStyles := "bearer, basic, header:name, query:param, body:path, form:field"
			return nil, fmt.Errorf("unknown injection style %q — valid styles: %s", spec, validStyles)
		}

		injections = append(injections, inj)
	}

	return injections, nil
}

// ParseInjectionsJSON parses a JSON string of injections into proxy.Injection structs.
// Exported for testing.
func ParseInjectionsJSON(jsonStr string) ([]proxy.Injection, error) {
	var raw map[string]interface{}
	if err := json.Unmarshal([]byte(jsonStr), &raw); err != nil {
		return nil, fmt.Errorf("invalid injections JSON: %w", err)
	}
	return parseInjections(raw)
}
