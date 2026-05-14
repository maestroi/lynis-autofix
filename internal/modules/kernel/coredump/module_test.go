package coredump_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/maestroi/hardener/internal/model"
	coredumpmod "github.com/maestroi/hardener/internal/modules/kernel/coredump"
	"github.com/maestroi/hardener/internal/testhelpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const limitsHardened = `# /etc/security/limits.conf
* hard core 0
`

const limitsDefault = `# /etc/security/limits.conf
# No core dump restriction configured.
`

func TestCoredumpModule_Metadata(t *testing.T) {
	m := coredumpmod.New()
	meta := m.Metadata()
	assert.Equal(t, "kernel-coredump", meta.ID)
	assert.Equal(t, model.RiskLow, meta.DefaultRisk)
	assert.Contains(t, meta.Tags, "network-safe")
	assert.Contains(t, meta.Tags, "docker-safe")
	assert.True(t, meta.CanRollback)
	assert.False(t, meta.RequiresReboot)
}

func TestCoredumpModule_SupportedFindings(t *testing.T) {
	m := coredumpmod.New()
	assert.Contains(t, m.SupportedFindings(), "KRNL-5820")
}

func TestCoredumpModule_Plan_BothAlreadySet_NotApplicable(t *testing.T) {
	fakeInspect := &testhelpers.FakeInspector{
		Files: map[string][]byte{
			coredumpmod.LimitsPath: []byte(limitsHardened),
		},
		SysctlValues: map[string]string{
			coredumpmod.SuidDumpableKey: "0",
		},
	}
	m := coredumpmod.New()
	finding := &model.Finding{ID: "KRNL-5820", Category: "KRNL"}

	action, err := m.Plan(context.Background(), finding, &model.Profile{}, fakeInspect)
	require.NoError(t, err)
	assert.False(t, action.Applicable)
	assert.NotEmpty(t, action.SkipReason)
}

func TestCoredumpModule_Plan_SysctlNotSet_Applicable(t *testing.T) {
	fakeInspect := &testhelpers.FakeInspector{
		Files: map[string][]byte{
			coredumpmod.LimitsPath: []byte(limitsHardened),
		},
		SysctlValues: map[string]string{
			coredumpmod.SuidDumpableKey: "2",
		},
	}
	m := coredumpmod.New()
	finding := &model.Finding{ID: "KRNL-5820", Category: "KRNL"}

	action, err := m.Plan(context.Background(), finding, &model.Profile{}, fakeInspect)
	require.NoError(t, err)
	assert.True(t, action.Applicable)
	assert.Len(t, action.Steps, 1)
	assert.Contains(t, action.Steps[0], coredumpmod.SuidDumpableKey)
}

func TestCoredumpModule_Plan_LimitsLineMissing_Applicable(t *testing.T) {
	fakeInspect := &testhelpers.FakeInspector{
		Files: map[string][]byte{
			coredumpmod.LimitsPath: []byte(limitsDefault),
		},
		SysctlValues: map[string]string{
			coredumpmod.SuidDumpableKey: "0",
		},
	}
	m := coredumpmod.New()
	finding := &model.Finding{ID: "KRNL-5820", Category: "KRNL"}

	action, err := m.Plan(context.Background(), finding, &model.Profile{}, fakeInspect)
	require.NoError(t, err)
	assert.True(t, action.Applicable)
	assert.Len(t, action.Steps, 1)
	assert.Contains(t, action.Steps[0], coredumpmod.LimitsPath)
}

func TestCoredumpModule_Apply_WritesLimitsAndSetsSysctl(t *testing.T) {
	fakeExec := &testhelpers.FakeExecutor{
		FakeInspector: testhelpers.FakeInspector{
			Files: map[string][]byte{
				coredumpmod.LimitsPath: []byte(limitsDefault),
			},
			SysctlValues: map[string]string{
				coredumpmod.SuidDumpableKey: "2",
			},
		},
	}

	m := coredumpmod.New()
	action := &model.PlannedAction{
		FindingID: "KRNL-5820",
		ModuleID:  "kernel-coredump",
		Metadata: map[string]string{
			"target_file": coredumpmod.LimitsPath,
			"sysctl_key":  coredumpmod.SuidDumpableKey,
		},
	}

	applied, err := m.Apply(context.Background(), action, fakeExec)
	require.NoError(t, err)
	assert.Equal(t, model.ActionApplied, applied.Status)
	assert.True(t, fakeExec.FileContains(coredumpmod.LimitsPath, coredumpmod.LimitsLine),
		"limits.conf must contain %q after Apply", coredumpmod.LimitsLine)
}

func TestCoredumpModule_Validate_BothPresent_NoError(t *testing.T) {
	fakeInspect := &testhelpers.FakeInspector{
		Files: map[string][]byte{
			coredumpmod.LimitsPath: []byte(limitsHardened),
		},
		SysctlValues: map[string]string{
			coredumpmod.SuidDumpableKey: "0",
		},
	}
	m := coredumpmod.New()
	err := m.Validate(context.Background(), &model.PlannedAction{FindingID: "KRNL-5820"}, fakeInspect)
	assert.NoError(t, err)
}

func TestCoredumpModule_Validate_SysctlWrong_ReturnsError(t *testing.T) {
	fakeInspect := &testhelpers.FakeInspector{
		Files: map[string][]byte{
			coredumpmod.LimitsPath: []byte(limitsHardened),
		},
		SysctlValues: map[string]string{
			coredumpmod.SuidDumpableKey: "1",
		},
	}
	m := coredumpmod.New()
	err := m.Validate(context.Background(), &model.PlannedAction{FindingID: "KRNL-5820"}, fakeInspect)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), coredumpmod.SuidDumpableKey)
}

func TestCoredumpModule_Rollback_RestoresLimitsFile(t *testing.T) {
	dir := t.TempDir()
	originalContent := []byte(limitsDefault)
	backupPath := filepath.Join(dir, "limits.conf.bak")
	require.NoError(t, os.WriteFile(backupPath, originalContent, 0644))

	fakeExec := &testhelpers.FakeExecutor{
		FakeInspector: testhelpers.FakeInspector{
			Files: map[string][]byte{backupPath: originalContent},
		},
	}

	m := coredumpmod.New()
	entry := &model.RollbackEntry{
		Kind:       model.RollbackFile,
		Path:       coredumpmod.LimitsPath,
		BackupPath: backupPath,
		OrigMode:   0644,
	}

	err := m.Rollback(context.Background(), entry, fakeExec)
	require.NoError(t, err)
	assert.True(t, fakeExec.HasWritten(coredumpmod.LimitsPath), "limits.conf must be restored")
}

func TestCoredumpModule_Rollback_SysctlKind_ReturnsNil(t *testing.T) {
	fakeExec := &testhelpers.FakeExecutor{}
	m := coredumpmod.New()
	entry := &model.RollbackEntry{
		Kind:        model.RollbackSysctl,
		SysctlKey:   coredumpmod.SuidDumpableKey,
		SysctlValue: "2",
	}

	err := m.Rollback(context.Background(), entry, fakeExec)
	assert.NoError(t, err)
}
