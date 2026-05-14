package acct_test

import (
	"context"
	"testing"

	"github.com/maestroi/hardener/internal/executor"
	"github.com/maestroi/hardener/internal/model"
	acctmod "github.com/maestroi/hardener/internal/modules/accounting/acct"
	"github.com/maestroi/hardener/internal/testhelpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAcct_Metadata(t *testing.T) {
	m := acctmod.New()
	meta := m.Metadata()
	assert.Equal(t, "accounting-acct", meta.ID)
	assert.Contains(t, meta.SupportedDistros, "ubuntu")
	assert.True(t, meta.CanRollback)
}

func TestAcct_SupportedFindings(t *testing.T) {
	assert.Contains(t, acctmod.New().SupportedFindings(), "ACCT-9622")
}

func TestAcct_Plan_InstalledAndEnabled_NotApplicable(t *testing.T) {
	inspect := &testhelpers.FakeInspector{
		InstalledPkgs: map[string]bool{"acct": true},
		Services: map[string]executor.ServiceStatus{
			"acct": {Name: "acct", Active: true, Enabled: true},
		},
	}
	m := acctmod.New()
	action, err := m.Plan(context.Background(), &model.Finding{ID: "ACCT-9622"}, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.False(t, action.Applicable)
}

func TestAcct_Plan_NotInstalled_Applicable(t *testing.T) {
	inspect := &testhelpers.FakeInspector{InstalledPkgs: map[string]bool{}}
	m := acctmod.New()
	action, err := m.Plan(context.Background(), &model.Finding{ID: "ACCT-9622"}, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.True(t, action.Applicable)
}

func TestAcct_Apply_InstallsEnablesStarts(t *testing.T) {
	exec := &testhelpers.FakeExecutor{
		FakeInspector: testhelpers.FakeInspector{InstalledPkgs: map[string]bool{}},
	}
	m := acctmod.New()
	action := &model.PlannedAction{FindingID: "ACCT-9622", ModuleID: "accounting-acct"}

	applied, err := m.Apply(context.Background(), action, exec)
	require.NoError(t, err)
	assert.Equal(t, model.ActionApplied, applied.Status)
	assert.True(t, exec.PackageInstalled("acct"))
	assert.True(t, testhelpers.ContainsService(exec.EnabledServices, "acct"))
	assert.True(t, testhelpers.ContainsService(exec.StartedServices, "acct"))
}

func TestAcct_Validate_ActiveAndEnabled_NoError(t *testing.T) {
	inspect := &testhelpers.FakeInspector{
		InstalledPkgs: map[string]bool{"acct": true},
		Services: map[string]executor.ServiceStatus{
			"acct": {Name: "acct", Active: true, Enabled: true},
		},
	}
	m := acctmod.New()
	err := m.Validate(context.Background(), &model.PlannedAction{FindingID: "ACCT-9622"}, inspect)
	assert.NoError(t, err)
}

func TestAcct_Validate_Inactive_Error(t *testing.T) {
	inspect := &testhelpers.FakeInspector{
		InstalledPkgs: map[string]bool{"acct": true},
		Services: map[string]executor.ServiceStatus{
			"acct": {Name: "acct", Active: false, Enabled: true},
		},
	}
	m := acctmod.New()
	err := m.Validate(context.Background(), &model.PlannedAction{FindingID: "ACCT-9622"}, inspect)
	assert.Error(t, err)
}
