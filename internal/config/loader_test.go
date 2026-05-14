package config_test

import (
	"testing"

	"github.com/maestroi/hardener/internal/config"
	"github.com/maestroi/hardener/internal/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadBundledProfile_Server(t *testing.T) {
	p, err := config.LoadBundledProfile("server")
	require.NoError(t, err)
	assert.Equal(t, "server", p.Name)
	assert.Equal(t, model.RiskHigh, p.MaxRiskLevel)
	assert.Equal(t, model.FailureRollbackAndStop, p.FailurePolicy)
	assert.True(t, p.SysctlPolicy.AllowNetworkChanges)
}

func TestLoadBundledProfile_Minimal(t *testing.T) {
	p, err := config.LoadBundledProfile("minimal")
	require.NoError(t, err)
	assert.Equal(t, "minimal", p.Name)
	assert.Equal(t, model.RiskLow, p.MaxRiskLevel)
	assert.Contains(t, p.BlockedModules, "firewall-baseline")
}

func TestLoadBundledProfile_DockerHost(t *testing.T) {
	p, err := config.LoadBundledProfile("docker-host")
	require.NoError(t, err)
	assert.Contains(t, p.BlockedModules, "firewall-baseline")
	assert.Contains(t, p.ProtectedServices, "docker")
	assert.False(t, p.SysctlPolicy.AllowNetworkChanges)
}

func TestLoadBundledProfile_ValidatorExample(t *testing.T) {
	p, err := config.LoadBundledProfile("validator-node.example")
	require.NoError(t, err)
	assert.Equal(t, model.RiskLow, p.MaxRiskLevel)
	assert.Contains(t, p.ProtectedProcesses, "lighthouse")
}

func TestLoadBundledProfile_Unknown(t *testing.T) {
	_, err := config.LoadBundledProfile("does-not-exist")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "does-not-exist")
}

func TestLoadConfigFromBytes_Defaults(t *testing.T) {
	cfg, err := config.LoadConfigFromBytes([]byte("version: \"1\"\n"))
	require.NoError(t, err)
	assert.Equal(t, "server", cfg.Profile)
	assert.Equal(t, "/var/lib/hardener", cfg.StateDir)
	assert.Equal(t, "table", cfg.Output)
}
