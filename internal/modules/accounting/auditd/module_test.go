package auditd_test

import (
	"context"
	"testing"

	"github.com/maestroi/hardener/internal/executor"
	"github.com/maestroi/hardener/internal/model"
	auditdmod "github.com/maestroi/hardener/internal/modules/accounting/auditd"
	"github.com/maestroi/hardener/internal/testhelpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuditd_Metadata(t *testing.T) {
	m := auditdmod.New()
	meta := m.Metadata()
	assert.Equal(t, "accounting-auditd", meta.ID)
	assert.Contains(t, meta.SupportedDistros, "ubuntu")
	assert.True(t, meta.CanRollback)
}

func TestAuditd_SupportedFindings(t *testing.T) {
	findings := auditdmod.New().SupportedFindings()
	assert.Contains(t, findings, "ACCT-9626")
	assert.Contains(t, findings, "ACCT-9628")
}

func TestAuditd_Plan_InstalledAndEnabled_NotApplicable(t *testing.T) {
	inspect := &testhelpers.FakeInspector{
		InstalledPkgs: map[string]bool{"auditd": true},
		Services: map[string]executor.ServiceStatus{
			"auditd": {Name: "auditd", Active: true, Enabled: true},
		},
	}
	m := auditdmod.New()
	action, err := m.Plan(context.Background(), &model.Finding{ID: "ACCT-9626"}, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.False(t, action.Applicable)
}

func TestAuditd_Plan_NotInstalled_Applicable(t *testing.T) {
	inspect := &testhelpers.FakeInspector{InstalledPkgs: map[string]bool{}}
	m := auditdmod.New()
	action, err := m.Plan(context.Background(), &model.Finding{ID: "ACCT-9626"}, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.True(t, action.Applicable)
}

func TestAuditd_Apply_InstallsEnablesStarts(t *testing.T) {
	exec := &testhelpers.FakeExecutor{
		FakeInspector: testhelpers.FakeInspector{InstalledPkgs: map[string]bool{}},
	}
	m := auditdmod.New()
	action := &model.PlannedAction{FindingID: "ACCT-9626", ModuleID: "accounting-auditd"}

	applied, err := m.Apply(context.Background(), action, exec)
	require.NoError(t, err)
	assert.Equal(t, model.ActionApplied, applied.Status)
	assert.True(t, exec.PackageInstalled("auditd"))
	assert.True(t, testhelpers.ContainsService(exec.EnabledServices, "auditd"))
	assert.True(t, testhelpers.ContainsService(exec.StartedServices, "auditd"))
}

func TestAuditd_Validate_ActiveAndEnabled_NoError(t *testing.T) {
	inspect := &testhelpers.FakeInspector{
		InstalledPkgs: map[string]bool{"auditd": true},
		Services: map[string]executor.ServiceStatus{
			"auditd": {Name: "auditd", Active: true, Enabled: true},
		},
	}
	m := auditdmod.New()
	err := m.Validate(context.Background(), &model.PlannedAction{FindingID: "ACCT-9626"}, inspect)
	assert.NoError(t, err)
}

func TestAuditd_Validate_NotInstalled_Error(t *testing.T) {
	inspect := &testhelpers.FakeInspector{InstalledPkgs: map[string]bool{}}
	m := auditdmod.New()
	err := m.Validate(context.Background(), &model.PlannedAction{FindingID: "ACCT-9626"}, inspect)
	assert.Error(t, err)
}
