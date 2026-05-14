package pwquality_test

import (
	"context"
	"testing"

	"github.com/maestroi/hardener/internal/model"
	"github.com/maestroi/hardener/internal/modules/auth/pwquality"
	"github.com/maestroi/hardener/internal/testhelpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPwquality_Metadata(t *testing.T) {
	m := pwquality.New()
	meta := m.Metadata()
	assert.Equal(t, "auth-pam-pwquality", meta.ID)
	assert.Contains(t, meta.Tags, "network-safe")
	assert.Contains(t, meta.Tags, "docker-safe")
	assert.True(t, meta.CanRollback)
}

func TestPwquality_SupportedFindings(t *testing.T) {
	m := pwquality.New()
	assert.Contains(t, m.SupportedFindings(), "AUTH-9262")
}

func TestPwquality_Plan_AlreadyInstalled_NotApplicable(t *testing.T) {
	inspect := &testhelpers.FakeInspector{
		InstalledPkgs: map[string]bool{"libpam-pwquality": true},
	}
	m := pwquality.New()
	finding := &model.Finding{ID: "AUTH-9262", Category: "AUTH"}

	action, err := m.Plan(context.Background(), finding, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.False(t, action.Applicable)
	assert.NotEmpty(t, action.SkipReason)
}

func TestPwquality_Plan_NotInstalled_Applicable(t *testing.T) {
	inspect := &testhelpers.FakeInspector{
		InstalledPkgs: map[string]bool{},
	}
	m := pwquality.New()
	finding := &model.Finding{ID: "AUTH-9262", Category: "AUTH"}

	action, err := m.Plan(context.Background(), finding, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.True(t, action.Applicable)
	assert.NotEmpty(t, action.Steps)
}

func TestPwquality_Apply_InstallsPackage(t *testing.T) {
	exec := &testhelpers.FakeExecutor{}
	m := pwquality.New()
	action := &model.PlannedAction{
		FindingID: "AUTH-9262",
		ModuleID:  "auth-pam-pwquality",
		Metadata:  map[string]string{"package": "libpam-pwquality"},
	}

	applied, err := m.Apply(context.Background(), action, exec)
	require.NoError(t, err)
	assert.Equal(t, model.ActionApplied, applied.Status)
	assert.True(t, exec.PackageInstalled("libpam-pwquality"))
}

func TestPwquality_Validate_Installed_NoError(t *testing.T) {
	inspect := &testhelpers.FakeInspector{
		InstalledPkgs: map[string]bool{"libpam-pwquality": true},
	}
	m := pwquality.New()
	err := m.Validate(context.Background(), &model.PlannedAction{}, inspect)
	assert.NoError(t, err)
}

func TestPwquality_Validate_NotInstalled_Error(t *testing.T) {
	inspect := &testhelpers.FakeInspector{
		InstalledPkgs: map[string]bool{},
	}
	m := pwquality.New()
	err := m.Validate(context.Background(), &model.PlannedAction{}, inspect)
	assert.Error(t, err)
}

func TestPwquality_Rollback_PackageKind_NoOp(t *testing.T) {
	exec := &testhelpers.FakeExecutor{}
	m := pwquality.New()
	entry := &model.RollbackEntry{
		Kind:        model.RollbackPackage,
		PackageName: "libpam-pwquality",
	}
	err := m.Rollback(context.Background(), entry, exec)
	assert.NoError(t, err)
}

func TestPwquality_Rollback_UnexpectedKind_Error(t *testing.T) {
	exec := &testhelpers.FakeExecutor{}
	m := pwquality.New()
	entry := &model.RollbackEntry{Kind: model.RollbackFile}
	err := m.Rollback(context.Background(), entry, exec)
	assert.Error(t, err)
}
