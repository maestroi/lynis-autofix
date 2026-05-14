package unattended_test

import (
	"context"
	"testing"

	"github.com/maestroi/hardener/internal/executor"
	"github.com/maestroi/hardener/internal/model"
	unattendedmod "github.com/maestroi/hardener/internal/modules/packages/unattended"
	"github.com/maestroi/hardener/internal/testhelpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUnattended_Metadata(t *testing.T) {
	m := unattendedmod.New()
	meta := m.Metadata()
	assert.Equal(t, "pkgs-unattended-upgrades", meta.ID)
	assert.Contains(t, meta.SupportedDistros, "ubuntu")
	assert.True(t, meta.CanRollback)
}

func TestUnattended_SupportedFindings(t *testing.T) {
	assert.Contains(t, unattendedmod.New().SupportedFindings(), "PKGS-7370")
}

func TestUnattended_Plan_AlreadyInstalledAndEnabled_NotApplicable(t *testing.T) {
	inspect := &testhelpers.FakeInspector{
		InstalledPkgs: map[string]bool{"unattended-upgrades": true},
		Services: map[string]executor.ServiceStatus{
			"unattended-upgrades": {Name: "unattended-upgrades", Active: true, Enabled: true},
		},
	}
	m := unattendedmod.New()
	action, err := m.Plan(context.Background(), &model.Finding{ID: "PKGS-7370"}, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.False(t, action.Applicable)
	assert.NotEmpty(t, action.SkipReason)
}

func TestUnattended_Plan_NotInstalled_Applicable(t *testing.T) {
	inspect := &testhelpers.FakeInspector{
		InstalledPkgs: map[string]bool{},
	}
	m := unattendedmod.New()
	action, err := m.Plan(context.Background(), &model.Finding{ID: "PKGS-7370"}, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.True(t, action.Applicable)
}

func TestUnattended_Plan_InstalledButDisabled_Applicable(t *testing.T) {
	inspect := &testhelpers.FakeInspector{
		InstalledPkgs: map[string]bool{"unattended-upgrades": true},
		Services: map[string]executor.ServiceStatus{
			"unattended-upgrades": {Name: "unattended-upgrades", Active: false, Enabled: false},
		},
	}
	m := unattendedmod.New()
	action, err := m.Plan(context.Background(), &model.Finding{ID: "PKGS-7370"}, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.True(t, action.Applicable)
}

func TestUnattended_Apply_InstallsAndEnablesService(t *testing.T) {
	exec := &testhelpers.FakeExecutor{
		FakeInspector: testhelpers.FakeInspector{
			InstalledPkgs: map[string]bool{},
		},
	}
	m := unattendedmod.New()
	action := &model.PlannedAction{FindingID: "PKGS-7370", ModuleID: "pkgs-unattended-upgrades"}

	applied, err := m.Apply(context.Background(), action, exec)
	require.NoError(t, err)
	assert.Equal(t, model.ActionApplied, applied.Status)
	assert.True(t, exec.PackageInstalled("unattended-upgrades"))
	assert.True(t, testhelpers.ContainsService(exec.EnabledServices, "unattended-upgrades"))
	assert.True(t, testhelpers.ContainsService(exec.StartedServices, "unattended-upgrades"))
}

func TestUnattended_Apply_AlreadyInstalled_OnlyEnablesService(t *testing.T) {
	exec := &testhelpers.FakeExecutor{
		FakeInspector: testhelpers.FakeInspector{
			InstalledPkgs: map[string]bool{"unattended-upgrades": true},
		},
	}
	m := unattendedmod.New()
	action := &model.PlannedAction{
		FindingID: "PKGS-7370",
		ModuleID:  "pkgs-unattended-upgrades",
		Metadata:  map[string]string{"skip_install": "true"},
	}

	_, err := m.Apply(context.Background(), action, exec)
	require.NoError(t, err)
	assert.Empty(t, exec.InstalledPackages, "should not reinstall if skip_install set")
	assert.True(t, testhelpers.ContainsService(exec.EnabledServices, "unattended-upgrades"))
}

func TestUnattended_Validate_ActiveAndEnabled_NoError(t *testing.T) {
	inspect := &testhelpers.FakeInspector{
		InstalledPkgs: map[string]bool{"unattended-upgrades": true},
		Services: map[string]executor.ServiceStatus{
			"unattended-upgrades": {Name: "unattended-upgrades", Active: true, Enabled: true},
		},
	}
	m := unattendedmod.New()
	err := m.Validate(context.Background(), &model.PlannedAction{FindingID: "PKGS-7370"}, inspect)
	assert.NoError(t, err)
}

func TestUnattended_Validate_Inactive_Error(t *testing.T) {
	inspect := &testhelpers.FakeInspector{
		InstalledPkgs: map[string]bool{"unattended-upgrades": true},
		Services: map[string]executor.ServiceStatus{
			"unattended-upgrades": {Name: "unattended-upgrades", Active: false, Enabled: true},
		},
	}
	m := unattendedmod.New()
	err := m.Validate(context.Background(), &model.PlannedAction{FindingID: "PKGS-7370"}, inspect)
	assert.Error(t, err)
}
