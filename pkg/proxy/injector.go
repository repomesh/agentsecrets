package proxy

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// Inject applies a single credential injection to the outbound request.
// Dispatches to the appropriate injection function based on style.
func Inject(req *http.Request, cred string, inj Injection) error {
	switch inj.Style {
	case "bearer":
		return injectBearer(req, cred)
	case "basic":
		return injectBasic(req, cred)
	case "header":
		return injectHeader(req, cred, inj.Target)
	case "query":
		return injectQuery(req, cred, inj.Target)
	case "body":
		return injectBody(req, cred, inj.Target)
	case "form":
		return injectForm(req, cred, inj.Target)
	default:
		return fmt.Errorf("unknown auth style: %q — must be bearer, basic, header, query, body, or form", inj.Style)
	}
}

// injectBearer sets Authorization: Bearer <token>.
func injectBearer(req *http.Request, token string) error {
	if token == "" {
		return fmt.Errorf("bearer token is empty")
	}
	req.Header.Set("Authorization", "Bearer "+token)
	return nil
}

// injectBasic sets Authorization: Basic base64(username:password).
// The credential must be in "username:password" format.
func injectBasic(req *http.Request, credentials string) error {
	parts := strings.SplitN(credentials, ":", 2)
	if len(parts) != 2 {
		return fmt.Errorf("basic auth secret must be in format username:password")
	}
	encoded := base64.StdEncoding.EncodeToString([]byte(credentials))
	req.Header.Set("Authorization", "Basic "+encoded)
	return nil
}

// injectHeader sets a custom header: <headerName>: <value>.
func injectHeader(req *http.Request, value string, headerName string) error {
	if headerName == "" {
		return fmt.Errorf("header name is required for auth style \"header\"")
	}
	req.Header.Set(headerName, value)
	return nil
}

// injectQuery appends a query parameter: ?paramName=<value>.
func injectQuery(req *http.Request, value string, paramName string) error {
	if paramName == "" {
		return fmt.Errorf("query param name is required for auth style \"query\"")
	}
	q := req.URL.Query()
	q.Set(paramName, value)
	req.URL.RawQuery = q.Encode()
	return nil
}

// injectBody injects a value into a JSON request body at the given dot-separated path.
// For example, path "auth.key" sets {"auth": {"key": "<value>"}} in the body.
// If the body is empty, a new JSON object is created.
func injectBody(req *http.Request, value string, path string) error {
	if path == "" {
		return fmt.Errorf("body path is required for auth style \"body\"")
	}

	// Read existing body (may be empty)
	var bodyMap map[string]interface{}
	if req.Body != nil {
		existing, err := io.ReadAll(req.Body)
		if err != nil {
			return fmt.Errorf("failed to read request body: %w", err)
		}
		if len(existing) > 0 {
			if err := json.Unmarshal(existing, &bodyMap); err != nil {
				return fmt.Errorf("body is not valid JSON: %w", err)
			}
		}
	}
	if bodyMap == nil {
		bodyMap = make(map[string]interface{})
	}

	// Set value at nested path (e.g. "auth.key" → bodyMap["auth"]["key"])
	parts := strings.Split(path, ".")
	current := bodyMap
	for i, part := range parts {
		if i == len(parts)-1 {
			// Last segment — set the value
			current[part] = value
		} else {
			// Intermediate segment — create nested map if needed
			next, ok := current[part]
			if !ok {
				next = make(map[string]interface{})
				current[part] = next
			}
			nested, ok := next.(map[string]interface{})
			if !ok {
				return fmt.Errorf("body path conflict: %q is not an object", part)
			}
			current = nested
		}
	}

	// Marshal back and replace body
	newBody, err := json.Marshal(bodyMap)
	if err != nil {
		return fmt.Errorf("failed to marshal body: %w", err)
	}
	req.Body = io.NopCloser(bytes.NewReader(newBody))
	req.ContentLength = int64(len(newBody))
	req.Header.Set("Content-Type", "application/json")
	return nil
}

// injectForm injects a value into a URL-encoded form body.
// If the body already has form data it is preserved; the new key is added/overwritten.
func injectForm(req *http.Request, value string, key string) error {
	if key == "" {
		return fmt.Errorf("form key is required for auth style \"form\"")
	}

	// Parse existing form body
	var form url.Values
	if req.Body != nil {
		existing, err := io.ReadAll(req.Body)
		if err != nil {
			return fmt.Errorf("failed to read request body: %w", err)
		}
		if len(existing) > 0 {
			form, err = url.ParseQuery(string(existing))
			if err != nil {
				return fmt.Errorf("body is not valid form data: %w", err)
			}
		}
	}
	if form == nil {
		form = make(url.Values)
	}

	form.Set(key, value)

	encoded := form.Encode()
	req.Body = io.NopCloser(strings.NewReader(encoded))
	req.ContentLength = int64(len(encoded))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return nil
}
