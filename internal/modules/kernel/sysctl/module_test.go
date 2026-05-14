package sysctl_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/maestroi/hardener/internal/executor"
	"github.com/maestroi/hardener/internal/model"
	sysctlmod "github.com/maestroi/hardener/internal/modules/kernel/sysctl"
	"github.com/maestroi/hardener/internal/testhelpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func allHardenedSysctls() map[string]string {
	return map[string]string{
		"net.ipv4.conf.all.accept_redirects":        "0",
		"net.ipv4.conf.default.accept_redirects":    "0",
		"net.ipv6.conf.all.accept_redirects":        "0",
		"net.ipv6.conf.default.accept_redirects":    "0",
		"net.ipv4.conf.all.send_redirects":          "0",
		"net.ipv4.conf.default.send_redirects":      "0",
		"net.ipv4.conf.all.accept_source_route":     "0",
		"net.ipv4.conf.default.accept_source_route": "0",
		"net.ipv4.tcp_syncookies":                   "1",
		"net.ipv4.conf.all.log_martians":            "1",
		"net.ipv4.conf.default.log_martians":        "1",
		"kernel.dmesg_restrict":                     "1",
		"kernel.kptr_restrict":                      "2",
		"kernel.sysrq":                              "0",
		"kernel.core_uses_pid":                      "1",
	}
}

func TestSysctlModule_Metadata(t *testing.T) {
	m := sysctlmod.New()
	meta := m.Metadata()
	assert.Equal(t, "kernel-sysctl", meta.ID)
	assert.Equal(t, model.RiskMedium, meta.DefaultRisk)
	assert.Contains(t, meta.Tags, "network-safe")
	assert.NotContains(t, meta.Tags, "docker-safe")
	assert.True(t, meta.CanRollback)
	assert.False(t, meta.RequiresReboot)
}

func TestSysctlModule_SupportedFindings(t *testing.T) {
	m := sysctlmod.New()
	assert.Contains(t, m.SupportedFindings(), "KRNL-6000")
}

func TestSysctlModule_Plan_AlreadyHardened_NotApplicable(t *testing.T) {
	fakeInspect := &testhelpers.FakeInspector{
		SysctlValues: allHardenedSysctls(),
	}
	m := sysctlmod.New()
	finding := &model.Finding{ID: "KRNL-6000", Category: "KRNL"}

	action, err := m.Plan(context.Background(), finding, &model.Profile{}, fakeInspect)
	require.NoError(t, err)
	assert.False(t, action.Applicable)
	assert.NotEmpty(t, action.SkipReason)
}

func TestSysctlModule_Plan_NeedsChanges_Applicable(t *testing.T) {
	fakeInspect := &testhelpers.FakeInspector{
		SysctlValues: map[string]string{},
	}
	m := sysctlmod.New()
	finding := &model.Finding{ID: "KRNL-6000", Category: "KRNL"}

	action, err := m.Plan(context.Background(), finding, &model.Profile{}, fakeInspect)
	require.NoError(t, err)
	assert.True(t, action.Applicable)
	assert.Len(t, action.Steps, 15)
	assert.Equal(t, sysctlmod.ConfPath, action.Metadata["target_file"])
}

func TestSysctlModule_Apply_WritesConfAndRunsSysctl(t *testing.T) {
	var sysctlSystemCalled bool
	fakeExec := &testhelpers.FakeExecutor{
		FakeInspector: testhelpers.FakeInspector{
			SysctlValues: map[string]string{},
		},
		RunFn: func(name string, args ...string) (executor.CmdOutput, error) {
			if name == "sysctl" && len(args) == 1 && args[0] == "--system" {
				sysctlSystemCalled = true
			}
			return executor.CmdOutput{}, nil
		},
	}

	m := sysctlmod.New()
	action := &model.PlannedAction{
		FindingID: "KRNL-6000",
		ModuleID:  "kernel-sysctl",
		Metadata:  map[string]string{"target_file": sysctlmod.ConfPath},
	}

	applied, err := m.Apply(context.Background(), action, fakeExec)
	require.NoError(t, err)
	assert.Equal(t, model.ActionApplied, applied.Status)
	assert.True(t, fakeExec.HasWritten(sysctlmod.ConfPath))
	assert.True(t, fakeExec.FileContains(sysctlmod.ConfPath, "net.ipv4.tcp_syncookies = 1"))
	assert.True(t, fakeExec.FileContains(sysctlmod.ConfPath, "kernel.kptr_restrict = 2"))
	assert.True(t, sysctlSystemCalled, "sysctl --system must be called after writing the conf")
}

func TestSysctlModule_Validate_AllValuesPresent_NoError(t *testing.T) {
	fakeInspect := &testhelpers.FakeInspector{
		SysctlValues: allHardenedSysctls(),
	}
	m := sysctlmod.New()
	err := m.Validate(context.Background(), &model.PlannedAction{FindingID: "KRNL-6000"}, fakeInspect)
	assert.NoError(t, err)
}

func TestSysctlModule_Validate_ValueMissing_ReturnsError(t *testing.T) {
	vals := allHardenedSysctls()
	vals["kernel.kptr_restrict"] = "0"
	fakeInspect := &testhelpers.FakeInspector{SysctlValues: vals}

	m := sysctlmod.New()
	err := m.Validate(context.Background(), &model.PlannedAction{FindingID: "KRNL-6000"}, fakeInspect)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "kernel.kptr_restrict")
}

func TestSysctlModule_Rollback_RestoresFileAndRunsSysctl(t *testing.T) {
	dir := t.TempDir()
	backupContent := []byte("# original empty conf\n")
	backupPath := filepath.Join(dir, "backup_99-hardener.conf")
	require.NoError(t, os.WriteFile(backupPath, backupContent, 0644))

	var sysctlSystemCalled bool
	fakeExec := &testhelpers.FakeExecutor{
		FakeInspector: testhelpers.FakeInspector{
			Files: map[string][]byte{backupPath: backupContent},
		},
		RunFn: func(name string, args ...string) (executor.CmdOutput, error) {
			if name == "sysctl" && len(args) == 1 && args[0] == "--system" {
				sysctlSystemCalled = true
			}
			return executor.CmdOutput{}, nil
		},
	}

	m := sysctlmod.New()
	entry := &model.RollbackEntry{
		Kind:       model.RollbackFile,
		Path:       sysctlmod.ConfPath,
		BackupPath: backupPath,
		OrigMode:   0644,
	}

	err := m.Rollback(context.Background(), entry, fakeExec)
	require.NoError(t, err)
	assert.True(t, fakeExec.HasWritten(sysctlmod.ConfPath))
	assert.True(t, sysctlSystemCalled)
}
