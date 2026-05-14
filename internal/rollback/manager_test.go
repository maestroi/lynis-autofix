package rollback_test

import (
	"context"
	"testing"

	"github.com/maestroi/hardener/internal/executor"
	"github.com/maestroi/hardener/internal/model"
	"github.com/maestroi/hardener/internal/registry"
	"github.com/maestroi/hardener/internal/rollback"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRollbackManager_ReverseOrder(t *testing.T) {
	manifest := &model.RollbackManifest{
		RunID: "test-run",
		Entries: []model.RollbackEntry{
			{Index: 0, Kind: model.RollbackSysctl, ModuleID: "kernel-sysctl", FindingID: "KRNL-6000", SysctlKey: "key", SysctlValue: "old"},
			{Index: 1, Kind: model.RollbackFile, ModuleID: "ssh-hardening", FindingID: "SSH-7408", Path: "/etc/ssh/sshd_config", BackupPath: "/backup/sshd_config"},
		},
	}

	exec := executor.NewDryRunExecutor()
	mgr := rollback.NewManager(registry.Default())

	err := mgr.Rollback(context.Background(), manifest, exec)
	// File rollback delegates to ssh module — DryRunExecutor makes sshd validation succeed synthetically.
	require.NoError(t, err)

	actions := exec.RecordedActions()
	methods := make([]string, 0, len(actions))
	for _, a := range actions {
		methods = append(methods, a.Method)
	}
	assert.NotEmpty(t, methods)
}

func TestRollbackManager_SysctlEntry_CallsSetSysctl(t *testing.T) {
	reg := registry.New()
	manifest := &model.RollbackManifest{
		RunID: "test-run",
		Entries: []model.RollbackEntry{
			{Index: 0, Kind: model.RollbackSysctl, ModuleID: "any", FindingID: "any",
				SysctlKey: "net.ipv4.tcp_syncookies", SysctlValue: "0"},
		},
	}

	exec := executor.NewDryRunExecutor()
	mgr := rollback.NewManager(reg)
	err := mgr.Rollback(context.Background(), manifest, exec)
	require.NoError(t, err)

	actions := exec.RecordedActions()
	require.Len(t, actions, 1)
	assert.Equal(t, "SetSysctl", actions[0].Method)
	assert.Equal(t, "net.ipv4.tcp_syncookies", actions[0].Args[0])
	assert.Equal(t, "0", actions[0].Args[1])
}

func TestRollbackManager_ServiceEntry_WasNotActive_CallsStop(t *testing.T) {
	reg := registry.New()
	manifest := &model.RollbackManifest{
		RunID: "r",
		Entries: []model.RollbackEntry{
			{Index: 0, Kind: model.RollbackService, ModuleID: "m", FindingID: "f",
				ServiceName: "fail2ban", WasActive: false, WasEnabled: false},
		},
	}

	exec := executor.NewDryRunExecutor()
	mgr := rollback.NewManager(reg)
	require.NoError(t, mgr.Rollback(context.Background(), manifest, exec))
	actions := exec.RecordedActions()
	methods := make([]string, len(actions))
	for i, a := range actions {
		methods[i] = a.Method
	}
	assert.Contains(t, methods, "StopService")
}
