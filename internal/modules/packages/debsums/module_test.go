package debsums_test

import (
	"context"
	"testing"

	"github.com/maestroi/hardener/internal/model"
	debsumsmod "github.com/maestroi/hardener/internal/modules/packages/debsums"
	"github.com/maestroi/hardener/internal/testhelpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDebsums_Metadata(t *testing.T) {
	m := debsumsmod.New()
	meta := m.Metadata()
	assert.Equal(t, "pkgs-debsums", meta.ID)
	assert.Contains(t, meta.SupportedDistros, "ubuntu")
	assert.True(t, meta.CanRollback)
	assert.False(t, meta.RequiresReboot)
}

func TestDebsums_SupportedFindings(t *testing.T) {
	findings := debsumsmod.New().SupportedFindings()
	assert.Contains(t, findings, "PKGS-7394")
	assert.Contains(t, findings, "TOOL-5002")
}

func TestDebsums_Plan_AlreadyInstalled_NotApplicable(t *testing.T) {
	inspect := &testhelpers.FakeInspector{
		InstalledPkgs: map[string]bool{"debsums": true},
	}
	m := debsumsmod.New()
	action, err := m.Plan(context.Background(), &model.Finding{ID: "PKGS-7394"}, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.False(t, action.Applicable)
	assert.NotEmpty(t, action.SkipReason)
}

func TestDebsums_Plan_NotInstalled_Applicable(t *testing.T) {
	inspect := &testhelpers.FakeInspector{
		InstalledPkgs: map[string]bool{},
	}
	m := debsumsmod.New()
	action, err := m.Plan(context.Background(), &model.Finding{ID: "PKGS-7394"}, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.True(t, action.Applicable)
	assert.NotEmpty(t, action.Steps)
}

func TestDebsums_Apply_InstallsPackage(t *testing.T) {
	exec := &testhelpers.FakeExecutor{
		FakeInspector: testhelpers.FakeInspector{
			InstalledPkgs: map[string]bool{},
		},
	}
	m := debsumsmod.New()
	action := &model.PlannedAction{FindingID: "PKGS-7394", ModuleID: "pkgs-debsums"}

	applied, err := m.Apply(context.Background(), action, exec)
	require.NoError(t, err)
	assert.Equal(t, model.ActionApplied, applied.Status)
	assert.True(t, exec.PackageInstalled("debsums"))
}

func TestDebsums_Validate_PackagePresent_NoError(t *testing.T) {
	inspect := &testhelpers.FakeInspector{
		InstalledPkgs: map[string]bool{"debsums": true},
	}
	m := debsumsmod.New()
	err := m.Validate(context.Background(), &model.PlannedAction{FindingID: "PKGS-7394"}, inspect)
	assert.NoError(t, err)
}

func TestDebsums_Validate_PackageMissing_Error(t *testing.T) {
	inspect := &testhelpers.FakeInspector{
		InstalledPkgs: map[string]bool{},
	}
	m := debsumsmod.New()
	err := m.Validate(context.Background(), &model.PlannedAction{FindingID: "PKGS-7394"}, inspect)
	assert.Error(t, err)
}

func TestDebsums_Rollback_PackageNotPreInstalled_IsNoOp(t *testing.T) {
	exec := &testhelpers.FakeExecutor{}
	m := debsumsmod.New()
	entry := &model.RollbackEntry{
		Kind:         model.RollbackPackage,
		PackageName:  "debsums",
		WasInstalled: false,
	}
	// MVP: package rollback is a no-op to avoid dependency surprises.
	err := m.Rollback(context.Background(), entry, exec)
	assert.NoError(t, err)
}
