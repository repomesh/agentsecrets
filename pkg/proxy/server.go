package proxy

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// Server is the HTTP proxy server that wraps the Engine.
// It listens for incoming requests with X-AS-* headers, builds
// CallRequests, executes them through the engine, and returns responses.
type Server struct {
	Port   int
	Engine *Engine
	mux    *http.ServeMux
}

// NewServer creates a proxy server bound to the given port and engine.
func NewServer(port int, engine *Engine) *Server {
	s := &Server{
		Port:   port,
		Engine: engine,
		mux:    http.NewServeMux(),
	}
	s.mux.HandleFunc("/proxy", s.handleProxy)
	s.mux.HandleFunc("/health", s.handleHealth)
	s.mux.HandleFunc("/sync", s.handleSync)
	return s
}

// Start begins listening and serving. This blocks until the server is stopped.
func (s *Server) Start() error {
	addr := fmt.Sprintf("localhost:%d", s.Port)

	// Launch background sync worker if audit logger is present
	if s.Engine.Audit != nil {
		go func() {
			for {
				time.Sleep(60 * time.Second)
				_ = s.Engine.Audit.SyncUnpushedLogs()
			}
		}()
	}

	return http.ListenAndServe(addr, s.mux)
}

// handleHealth is a simple health check endpoint.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	lastSync, revoked := s.Engine.GetState()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":        "ok",
		"project":       s.Engine.ProjectID,
		"last_sync":      lastSync.Format(time.RFC3339),
		"revoked_count": len(revoked),
		"revoked_ids":   revoked,
	})
}

// handleSync forces an immediate revocation list sync.
func (s *Server) handleSync(w http.ResponseWriter, r *http.Request) {
	s.Engine.Sync()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "ok",
		"message": "revocation sync triggered",
	})
}

// handleProxy processes incoming proxy requests.
//
// Required headers:
//   - X-AS-Target-URL: The upstream URL to call
//
// Injection headers (at least one required):
//   - X-AS-Inject-Bearer: SECRET_KEY       → Authorization: Bearer <value>
//   - X-AS-Inject-Basic: SECRET_KEY        → Authorization: Basic base64(<value>)
//   - X-AS-Inject-Header-<Name>: SECRET_KEY → <Name>: <value>
//   - X-AS-Inject-Query-<Param>: SECRET_KEY → ?Param=<value>
//   - X-AS-Inject-Body-<Path>: SECRET_KEY   → body.Path = <value>
//   - X-AS-Inject-Form-<Key>: SECRET_KEY    → form key = <value>
//
// Optional headers:
//   - X-AS-Method: HTTP method (default: GET)
//   - X-AS-Agent-ID: Agent identifier for audit logging
func (s *Server) handleProxy(w http.ResponseWriter, r *http.Request) {
	targetURL := r.Header.Get("X-AS-Target-URL")
	if targetURL == "" {
		writeError(w, 400, "X-AS-Target-URL header is required")
		return
	}

	method := r.Header.Get("X-AS-Method")
	if method == "" {
		method = r.Method
	}

	agentID := r.Header.Get("X-AS-Agent-ID")
	agentToken := r.Header.Get("X-AS-Agent-Token")

	if agentToken == "" {
		agentToken = os.Getenv("AS_AGENT_TOKEN")
	}

	identityLevel := "anonymous"
	tokenID := ""
	if agentToken != "" {
		identityLevel = "issued"
		tokenID = agentToken // or parsed token if identifiable
		// If the token matches the environment token, that's what we use.
		// For now, the backend will validate it; we just pass it along.
		// If agentID is empty, backend will infer it from token.
	} else if agentID != "" {
		identityLevel = "declared"
	}

	// Parse injection headers
	injections := parseInjections(r.Header)
	if len(injections) == 0 {
		writeError(w, 400, "At least one X-AS-Inject-* header is required")
		return
	}

	// Read request body
	var body []byte
	if r.Body != nil {
		var err error
		body, err = io.ReadAll(r.Body)
		if err != nil {
			writeError(w, 400, "Failed to read request body")
			return
		}
	}

	// Build extra headers (everything that's not X-AS-*)
	// Go's http.Header canonicalizes keys to "X-As-..." form
	headers := make(map[string]string)
	for k, v := range r.Header {
		if !strings.HasPrefix(k, "X-As-") {
			headers[k] = v[0]
		}
	}

	// Execute through engine
	result, err := s.Engine.Execute(CallRequest{
		TargetURL:     targetURL,
		Method:        method,
		Headers:       headers,
		Body:          body,
		Injections:    injections,
		AgentID:       agentID,
		IdentityLevel: identityLevel,
		TokenID:       tokenID,
	})

	if err != nil {
		writeError(w, 502, err.Error())
		return
	}

	// Forward upstream response
	for k, vals := range result.Headers {
		for _, v := range vals {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(result.StatusCode)
	w.Write(result.Body)
}

// parseInjections extracts all X-AS-Inject-* headers and converts them to Injections.
func parseInjections(headers http.Header) []Injection {
	var injections []Injection

	for key, values := range headers {
		secretKey := values[0]

		switch {
		case strings.EqualFold(key, "X-As-Inject-Bearer"):
			injections = append(injections, Injection{Style: "bearer", SecretKey: secretKey})

		case strings.EqualFold(key, "X-As-Inject-Basic"):
			injections = append(injections, Injection{Style: "basic", SecretKey: secretKey})

		case strings.HasPrefix(strings.ToLower(key), "x-as-inject-header-"):
			headerName := key[len("X-As-Inject-Header-"):]
			injections = append(injections, Injection{Style: "header", Target: headerName, SecretKey: secretKey})

		case strings.HasPrefix(strings.ToLower(key), "x-as-inject-query-"):
			paramName := key[len("X-As-Inject-Query-"):]
			injections = append(injections, Injection{Style: "query", Target: paramName, SecretKey: secretKey})

		case strings.HasPrefix(strings.ToLower(key), "x-as-inject-body-"):
			path := key[len("X-As-Inject-Body-"):]
			// Convert dashes to dots for nested paths: auth-key → auth.key
			path = strings.ReplaceAll(path, "-", ".")
			injections = append(injections, Injection{Style: "body", Target: path, SecretKey: secretKey})

		case strings.HasPrefix(strings.ToLower(key), "x-as-inject-form-"):
			formKey := key[len("X-As-Inject-Form-"):]
			injections = append(injections, Injection{Style: "form", Target: formKey, SecretKey: secretKey})
		}
	}

	return injections
}

// writeError writes a JSON error response.
func writeError(w http.ResponseWriter, statusCode int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(map[string]string{
		"error": message,
	})
}
