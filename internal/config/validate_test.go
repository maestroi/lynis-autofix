package config_test

import (
	"testing"

	"github.com/maestroi/hardener/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidate_OK(t *testing.T) {
	cfg, err := config.LoadConfigFromBytes([]byte("version: \"1\"\n"))
	require.NoError(t, err)
	require.NoError(t, config.Validate(cfg))
}

func TestValidate_EmptyStateDir(t *testing.T) {
	cfg, err := config.LoadConfigFromBytes([]byte("version: \"1\"\n"))
	require.NoError(t, err)
	cfg.StateDir = ""

	err = config.Validate(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "state_dir")
}

func TestValidate_EmptyProfile(t *testing.T) {
	cfg, err := config.LoadConfigFromBytes([]byte("version: \"1\"\n"))
	require.NoError(t, err)
	cfg.Profile = ""

	err = config.Validate(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "profile")
}

func TestValidate_InvalidOutput(t *testing.T) {
	cfg, err := config.LoadConfigFromBytes([]byte("version: \"1\"\n"))
	require.NoError(t, err)
	cfg.Output = "yaml"

	err = config.Validate(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid output format")
}

func TestValidate_OutputCaseInsensitive(t *testing.T) {
	cfg, err := config.LoadConfigFromBytes([]byte("version: \"1\"\n"))
	require.NoError(t, err)
	cfg.Output = "JSON"

	require.NoError(t, config.Validate(cfg))
}
