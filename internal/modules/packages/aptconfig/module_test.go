package aptconfig_test

import (
	"context"
	"testing"

	"github.com/maestroi/hardener/internal/model"
	"github.com/maestroi/hardener/internal/modules/packages/aptconfig"
	"github.com/maestroi/hardener/internal/testhelpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPlan_AlreadyCompliant(t *testing.T) {
	m := aptconfig.New()
	inspect := &testhelpers.FakeInspector{
		Files: map[string][]byte{
			aptconfig.ConfPath: []byte(aptconfig.ConfContent),
		},
	}
	action, err := m.Plan(context.Background(), &model.Finding{ID: "DEB-0280"}, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.False(t, action.Applicable)
	assert.NotEmpty(t, action.SkipReason)
}

func TestPlan_NotPresent(t *testing.T) {
	m := aptconfig.New()
	inspect := &testhelpers.FakeInspector{}
	action, err := m.Plan(context.Background(), &model.Finding{ID: "DEB-0880"}, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.True(t, action.Applicable)
	assert.Equal(t, model.RiskLow, action.Risk)
}

func TestApplyAndValidate(t *testing.T) {
	m := aptconfig.New()
	exec := &testhelpers.FakeExecutor{}

	action := &model.PlannedAction{FindingID: "DEB-0280", ModuleID: "pkgs-apt-config", Applicable: true}
	applied, err := m.Apply(context.Background(), action, exec)
	require.NoError(t, err)
	assert.Equal(t, model.ActionApplied, applied.Status)
	assert.True(t, exec.HasWritten(aptconfig.ConfPath))

	err = m.Validate(context.Background(), action, exec)
	assert.NoError(t, err)
}
