package safety_test

import (
	"context"
	"testing"

	"github.com/maestroi/hardener/internal/executor"
	"github.com/maestroi/hardener/internal/model"
	"github.com/maestroi/hardener/internal/safety"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProfileFilter_BlockedModule_NotSafe(t *testing.T) {
	profile := &model.Profile{BlockedModules: []string{"firewall-baseline"}, Name: "test"}
	filter := safety.NewProfileFilter(profile)

	action := &model.PlannedAction{ModuleID: "firewall-baseline", Applicable: true}
	result, err := filter.Check(context.Background(), action, executor.NewDryRunExecutor())
	require.NoError(t, err)
	assert.False(t, result.Safe)
	assert.Contains(t, result.Reason, "blocked by profile")
}

func TestProfileFilter_AllowedModule_Safe(t *testing.T) {
	profile := &model.Profile{BlockedModules: []string{"auditd-basic"}}
	filter := safety.NewProfileFilter(profile)

	action := &model.PlannedAction{ModuleID: "ssh-hardening", Applicable: true}
	result, err := filter.Check(context.Background(), action, executor.NewDryRunExecutor())
	require.NoError(t, err)
	assert.True(t, result.Safe)
}

func TestProfileFilter_ProtectedService_NetworkModule_NotSafe(t *testing.T) {
	profile := &model.Profile{ProtectedServices: []string{"docker"}}
	filter := safety.NewProfileFilter(profile)

	action := &model.PlannedAction{
		ModuleID:   "some-module",
		Applicable: true,
		Tags:       []string{"service-restart"},
		Metadata:   map[string]string{"service_name": "docker"},
	}
	result, err := filter.Check(context.Background(), action, executor.NewDryRunExecutor())
	require.NoError(t, err)
	assert.False(t, result.Safe)
	assert.Contains(t, result.Reason, "protected service")
}
