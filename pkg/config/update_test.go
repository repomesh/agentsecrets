package config

import (
	"fmt"
	"testing"
)

func TestIsNewer(t *testing.T) {
	tests := []struct {
		latest  string
		current string
		want    bool
	}{
		{"1.1.3", "1.1.2", true},
		{"1.3.0", "1.1.2", true},
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
