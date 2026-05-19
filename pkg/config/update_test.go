package config

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestIsNewer(t *testing.T) {
	tests := []struct {
		latest  string
		current string
		want    bool
	}{
		{"1.1.3", "1.1.2", true},
		{"1.3.1", "1.1.2", true},
		{"2.0.0", "1.1.2", true},
		{"1.1.2", "1.1.2", false},
		{"1.1.1", "1.1.2", false},
		{"1.1.2.1", "1.1.2", true},
		{"1.1.10", "1.1.2", true},
	}

	for _, tt := range tests {
		got := isNewer(tt.latest, tt.current)
		if got != tt.want {
			t.Errorf("isNewer(%s, %s) = %v; want %v", tt.latest, tt.current, got, tt.want)
		}
	}
	fmt.Println("✓ Version comparison tests passed")
}

func TestCheckForUpdatesAlertInterval(t *testing.T) {
	// Create a temp directory for mocking the home directory config files
	tmpDir, err := os.MkdirTemp("", "agentsecrets-test-")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Override HomeDirHook to use temp directory
	oldHook := HomeDirHook
	HomeDirHook = func() (string, error) {
		return tmpDir, nil
	}
	defer func() { HomeDirHook = oldHook }()

	// Initialize config directory and config file
	if err := os.MkdirAll(filepath.Join(tmpDir, ".agentsecrets"), 0755); err != nil {
		t.Fatalf("failed to create mock config dir: %v", err)
	}

	cfg := &GlobalConfig{
		LastUpdateCheck: time.Now().Unix() - 1000, // checked 1000s ago (within 24h)
		LatestVersion:   "1.5.0",
		LastUpdateAlert: 0, // never alerted
	}
	if err := SaveGlobalConfig(cfg); err != nil {
		t.Fatalf("failed to save mock config: %v", err)
	}

	// 1. First call: Should alert because LastUpdateAlert is 0 (or older than 6h)
	res, err := CheckForUpdates("1.4.0")
	if err != nil {
		t.Fatalf("CheckForUpdates failed: %v", err)
	}
	if res == nil || !res.NewVersionAvailable {
		t.Errorf("expected update alert, got nil or NewVersionAvailable=false")
	}

	// Reload config to verify LastUpdateAlert was updated
	cfg2, err := LoadGlobalConfig()
	if err != nil {
		t.Fatalf("LoadGlobalConfig failed: %v", err)
	}
	if cfg2.LastUpdateAlert == 0 {
		t.Errorf("expected LastUpdateAlert to be updated, got 0")
	}

	// 2. Second call (immediate): Should NOT alert because LastUpdateAlert is recent (within 6h)
	res2, err := CheckForUpdates("1.4.0")
	if err != nil {
		t.Fatalf("CheckForUpdates failed: %v", err)
	}
	if res2 != nil {
		t.Errorf("expected no alert, but got update result: %+v", res2)
	}

	// 3. Set LastUpdateAlert to 7 hours ago: Should alert again
	cfg2.LastUpdateAlert = time.Now().Unix() - (7 * 60 * 60)
	if err := SaveGlobalConfig(cfg2); err != nil {
		t.Fatalf("failed to update mock config: %v", err)
	}

	res3, err := CheckForUpdates("1.4.0")
	if err != nil {
		t.Fatalf("CheckForUpdates failed: %v", err)
	}
	if res3 == nil || !res3.NewVersionAvailable {
		t.Errorf("expected update alert after 7 hours, got nil or NewVersionAvailable=false")
	}
	fmt.Println("✓ Update check alert interval tests passed")
}

