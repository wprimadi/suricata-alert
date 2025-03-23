package config

import (
	"os"
	"testing"
)

func TestLoadEnv(t *testing.T) {
	os.Setenv("TEST_ENV", "true")
	err := LoadEnv()
	if err != nil {
		t.Fatalf("Failed to load env: %v", err)
	}
}
