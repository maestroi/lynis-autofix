package config

import (
	"fmt"

	"gopkg.in/yaml.v3"

	"github.com/maestroi/hardener/internal/embedfs"
	"github.com/maestroi/hardener/internal/model"
)

// Config is the merged configuration from all sources.
type Config struct {
	Version          string           `yaml:"version"`
	Profile          string           `yaml:"profile"`
	StateDir         string           `yaml:"state_dir"`
	Lynis            LynisConfig      `yaml:"lynis"`
	Output           string           `yaml:"output"`
	ConfirmDangerous bool             `yaml:"confirm_dangerous"`
	ProfileOverrides ProfileOverrides `yaml:"profile_overrides"`
}

// LynisConfig holds paths and flags for the Lynis binary.
type LynisConfig struct {
	Binary     string   `yaml:"binary"`
	ReportPath string   `yaml:"report_path"`
	LogPath    string   `yaml:"log_path"`
	ExtraFlags []string `yaml:"extra_flags"`
}

// ProfileOverrides contains additive overrides applied on top of the active profile.
type ProfileOverrides struct {
	AllowedModules      []string          `yaml:"allowed_modules"`
	BlockedModules      []string          `yaml:"blocked_modules"`
	ProtectedPorts      []int             `yaml:"protected_ports"`
	ProtectedPortRanges []model.PortRange `yaml:"protected_port_ranges"`
	ProtectedProcesses  []string          `yaml:"protected_processes"`
	ProtectedServices   []string          `yaml:"protected_services"`
}

// LoadBundledProfile loads and parses a bundled YAML profile by name (e.g. "server", "docker-host").
func LoadBundledProfile(name string) (*model.Profile, error) {
	data, err := embedfs.Profiles.ReadFile("profiles/" + name + ".yaml")
	if err != nil {
		return nil, fmt.Errorf("bundled profile %q not found", name)
	}
	var p model.Profile
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("parsing profile %q: %w", name, err)
	}
	return &p, nil
}

// LoadConfigFromBytes parses a YAML config document, applying defaults for missing fields.
func LoadConfigFromBytes(data []byte) (*Config, error) {
	cfg := defaults()
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}
	return &cfg, nil
}
