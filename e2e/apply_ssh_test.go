//go:build integration

package e2e_test

import (
	"context"
	"os"
	"testing"

	"github.com/maestroi/hardener/internal/backup"
	"github.com/maestroi/hardener/internal/executor"
	"github.com/maestroi/hardener/internal/model"
	sshmod "github.com/maestroi/hardener/internal/modules/ssh"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIntegration_SSHHardening_ApplyAndRollback(t *testing.T) {
	if os.Getenv("HARDENER_INTEGRATION") == "" {
		t.Skip("set HARDENER_INTEGRATION=1 to run integration tests")
	}
	if os.Getuid() != 0 {
		t.Fatal("integration tests must run as root")
	}

	ctx := context.Background()
	execLocal := executor.NewLocalExecutor()

	original, err := execLocal.ReadFile(ctx, sshmod.ConfigPath)
	require.NoError(t, err)

	backupDir := t.TempDir()
	bs := backup.NewStore(backupDir)
	entry, err := bs.SnapshotFile(ctx, "integration-test", "ssh-hardening", "SSH-7408", 0, sshmod.ConfigPath)
	require.NoError(t, err)

	m := sshmod.New()
	finding := &model.Finding{ID: "SSH-7408", Category: "SSH", Severity: model.SeverityWarning}
	profile := &model.Profile{MaxRiskLevel: model.RiskHigh}
	inspect := executor.NewLocalExecutor()

	action, err := m.Plan(ctx, finding, profile, inspect)
	require.NoError(t, err)

	if !action.Applicable {
		t.Logf("SSH-7408 not applicable on this system: %s", action.SkipReason)
		t.Skip("system already hardened, skipping apply test")
	}

	applied, err := m.Apply(ctx, action, execLocal)
	require.NoError(t, err, "Apply must succeed")
	assert.Equal(t, model.ActionApplied, applied.Status)

	err = m.Validate(ctx, action, inspect)
	assert.NoError(t, err, "Validate must pass after Apply")

	err = m.Rollback(ctx, &entry, execLocal)
	require.NoError(t, err, "Rollback must succeed")

	restored, err := execLocal.ReadFile(ctx, sshmod.ConfigPath)
	require.NoError(t, err)
	assert.Equal(t, string(original), string(restored), "file must be restored to original after rollback")
}

func TestIntegration_SSHHardening_Idempotent(t *testing.T) {
	if os.Getenv("HARDENER_INTEGRATION") == "" {
		t.Skip("set HARDENER_INTEGRATION=1 to run integration tests")
	}
	if os.Getuid() != 0 {
		t.Fatal("integration tests must run as root")
	}

	ctx := context.Background()
	execLocal := executor.NewLocalExecutor()
	inspect := executor.NewLocalExecutor()

	m := sshmod.New()
	finding := &model.Finding{ID: "SSH-7408", Category: "SSH"}
	profile := &model.Profile{MaxRiskLevel: model.RiskHigh}

	action1, err := m.Plan(ctx, finding, profile, inspect)
	require.NoError(t, err)
	if action1.Applicable {
		_, err = m.Apply(ctx, action1, execLocal)
		require.NoError(t, err)
	}

	action2, err := m.Plan(ctx, finding, profile, inspect)
	require.NoError(t, err)
	assert.False(t, action2.Applicable, "second Plan() must return not applicable — system already hardened")
}
