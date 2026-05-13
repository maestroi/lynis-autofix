package config

import (
	"fmt"
	"strings"
)

var validOutputFormats = map[string]bool{"table": true, "json": true}

// Validate checks the merged Config for invalid or conflicting values.
func Validate(cfg *Config) error {
	if cfg.StateDir == "" {
		return fmt.Errorf("state_dir must not be empty")
	}
	if cfg.Profile == "" {
		return fmt.Errorf("profile must not be empty")
	}
	if !validOutputFormats[strings.ToLower(cfg.Output)] {
		return fmt.Errorf("invalid output format %q (valid: table, json)", cfg.Output)
	}
	return nil
}
