package proxy

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestInjectBearer(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://api.example.com", nil)
	inj := Injection{Style: "bearer", SecretKey: "TEST_KEY"}
	err := Inject(req, "sk_test_123", inj)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := req.Header.Get("Authorization")
	want := "Bearer sk_test_123"
	if got != want {
		t.Errorf("Authorization header = %q, want %q", got, want)
	}
}

func TestInjectBearerEmpty(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://api.example.com", nil)
	inj := Injection{Style: "bearer", SecretKey: "TEST_KEY"}
	err := Inject(req, "", inj)

	if err == nil {
		t.Fatal("expected error for empty bearer token")
	}
}

func TestInjectBasic(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://api.example.com", nil)
	inj := Injection{Style: "basic", SecretKey: "TEST_KEY"}
	err := Inject(req, "myuser:mypass", inj)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := req.Header.Get("Authorization")
	// base64("myuser:mypass") = "bXl1c2VyOm15cGFzcw=="
	want := "Basic bXl1c2VyOm15cGFzcw=="
	if got != want {
		t.Errorf("Authorization header = %q, want %q", got, want)
	}
}

func TestInjectBasicBadFormat(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://api.example.com", nil)
	inj := Injection{Style: "basic", SecretKey: "TEST_KEY"}
	err := Inject(req, "nocolonhere", inj)

	if err == nil {
		t.Fatal("expected error for bad basic auth format")
	}
}

func TestInjectHeader(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://api.example.com", nil)
	inj := Injection{Style: "header", Target: "X-API-Key", SecretKey: "TEST_KEY"}
	err := Inject(req, "abc123", inj)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := req.Header.Get("X-API-Key")
	if got != "abc123" {
		t.Errorf("X-API-Key header = %q, want %q", got, "abc123")
	}
}

func TestInjectHeaderMissingTarget(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://api.example.com", nil)
	inj := Injection{Style: "header", Target: "", SecretKey: "TEST_KEY"}
	err := Inject(req, "abc123", inj)

	if err == nil {
		t.Fatal("expected error for missing header target")
	}
}

func TestInjectQuery(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://api.example.com/data", nil)
	inj := Injection{Style: "query", Target: "api_key", SecretKey: "TEST_KEY"}
	err := Inject(req, "key123", inj)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := req.URL.Query().Get("api_key")
	if got != "key123" {
		t.Errorf("query param api_key = %q, want %q", got, "key123")
	}
}

func TestInjectQueryPreservesExisting(t *testing.T) {
	u, _ := url.Parse("https://api.example.com/data?existing=yes")
	req := &http.Request{URL: u, Header: make(http.Header)}
	inj := Injection{Style: "query", Target: "api_key", SecretKey: "TEST_KEY"}
	err := Inject(req, "key123", inj)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.URL.Query().Get("existing") != "yes" {
		t.Error("existing query param was lost")
	}
	if req.URL.Query().Get("api_key") != "key123" {
		t.Error("new query param was not added")
	}
}

func TestInjectQueryMissingTarget(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://api.example.com", nil)
	inj := Injection{Style: "query", Target: "", SecretKey: "TEST_KEY"}
	err := Inject(req, "key123", inj)

	if err == nil {
		t.Fatal("expected error for missing query target")
	}
}

func TestInjectUnknownStyle(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://api.example.com", nil)
	inj := Injection{Style: "sigv4", SecretKey: "TEST_KEY"}
	err := Inject(req, "val", inj)

	if err == nil {
		t.Fatal("expected error for unknown style")
	}
}

func TestInjectBodyNestedPath(t *testing.T) {
	body := strings.NewReader(`{"amount": 1000}`)
	req, _ := http.NewRequest("POST", "https://api.example.com", body)
	inj := Injection{Style: "body", Target: "auth.key", SecretKey: "TEST_KEY"}
	err := Inject(req, "secret-val", inj)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	result, _ := io.ReadAll(req.Body)
	got := string(result)
	if !strings.Contains(got, `"auth"`) || !strings.Contains(got, `"key":"secret-val"`) {
		t.Errorf("body = %s, expected auth.key to be injected", got)
	}
	// Original field should be preserved
	if !strings.Contains(got, `"amount"`) {
		t.Error("original body field 'amount' was lost")
	}
}

func TestInjectBodyEmptyBody(t *testing.T) {
	req, _ := http.NewRequest("POST", "https://api.example.com", nil)
	inj := Injection{Style: "body", Target: "api_key", SecretKey: "TEST_KEY"}
	err := Inject(req, "key123", inj)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	result, _ := io.ReadAll(req.Body)
	got := string(result)
	if !strings.Contains(got, `"api_key":"key123"`) {
		t.Errorf("body = %s, expected api_key to be set", got)
	}
}

func TestInjectBodyMissingPath(t *testing.T) {
	req, _ := http.NewRequest("POST", "https://api.example.com", nil)
	inj := Injection{Style: "body", Target: "", SecretKey: "TEST_KEY"}
	err := Inject(req, "val", inj)

	if err == nil {
		t.Fatal("expected error for missing body path")
	}
}

func TestInjectFormNewBody(t *testing.T) {
	req, _ := http.NewRequest("POST", "https://api.example.com", nil)
	inj := Injection{Style: "form", Target: "api_key", SecretKey: "TEST_KEY"}
	err := Inject(req, "formval123", inj)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	result, _ := io.ReadAll(req.Body)
	got := string(result)
	if !strings.Contains(got, "api_key=formval123") {
		t.Errorf("form body = %q, expected api_key=formval123", got)
	}
	ct := req.Header.Get("Content-Type")
	if ct != "application/x-www-form-urlencoded" {
		t.Errorf("Content-Type = %q, want application/x-www-form-urlencoded", ct)
	}
}

func TestInjectFormExistingData(t *testing.T) {
	body := strings.NewReader("username=admin&action=login")
	req, _ := http.NewRequest("POST", "https://api.example.com", body)
	inj := Injection{Style: "form", Target: "password", SecretKey: "TEST_KEY"}
	err := Inject(req, "s3cret", inj)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	result, _ := io.ReadAll(req.Body)
	got := string(result)
	if !strings.Contains(got, "password=s3cret") {
		t.Errorf("form body = %q, expected password=s3cret", got)
	}
	if !strings.Contains(got, "username=admin") {
		t.Error("existing form field 'username' was lost")
	}
}

func TestInjectFormMissingKey(t *testing.T) {
	req, _ := http.NewRequest("POST", "https://api.example.com", nil)
	inj := Injection{Style: "form", Target: "", SecretKey: "TEST_KEY"}
	err := Inject(req, "val", inj)

	if err == nil {
		t.Fatal("expected error for missing form key")
	}
}
