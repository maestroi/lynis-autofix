package debsecan_test

import (
	"context"
	"testing"

	"github.com/maestroi/hardener/internal/model"
	"github.com/maestroi/hardener/internal/modules/packages/debsecan"
	"github.com/maestroi/hardener/internal/testhelpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPlan_AlreadyInstalled(t *testing.T) {
	m := debsecan.New()
	inspect := &testhelpers.FakeInspector{
		InstalledPkgs: map[string]bool{"debsecan": true},
	}
	action, err := m.Plan(context.Background(), &model.Finding{ID: "DEB-0811"}, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.False(t, action.Applicable)
	assert.NotEmpty(t, action.SkipReason)
}

func TestPlan_NotInstalled(t *testing.T) {
	m := debsecan.New()
	inspect := &testhelpers.FakeInspector{}
	action, err := m.Plan(context.Background(), &model.Finding{ID: "DEB-0811"}, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.True(t, action.Applicable)
}

func TestApplyAndValidate(t *testing.T) {
	m := debsecan.New()
	exec := &testhelpers.FakeExecutor{}
	action := &model.PlannedAction{FindingID: "DEB-0811", ModuleID: "pkgs-debsecan", Applicable: true}

	applied, err := m.Apply(context.Background(), action, exec)
	require.NoError(t, err)
	assert.Equal(t, model.ActionApplied, applied.Status)
	assert.True(t, exec.PackageInstalled("debsecan"))

	err = m.Validate(context.Background(), action, exec)
	assert.NoError(t, err)
}
