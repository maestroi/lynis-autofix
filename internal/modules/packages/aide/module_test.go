package aide_test

import (
	"context"
	"testing"

	"github.com/maestroi/hardener/internal/model"
	"github.com/maestroi/hardener/internal/modules/packages/aide"
	"github.com/maestroi/hardener/internal/testhelpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPlan_AlreadyInstalled(t *testing.T) {
	m := aide.New()
	inspect := &testhelpers.FakeInspector{
		InstalledPkgs: map[string]bool{"aide": true},
		Files:         map[string][]byte{aide.DBPath: {}},
	}
	action, err := m.Plan(context.Background(), &model.Finding{ID: "FINT-4350"}, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.False(t, action.Applicable)
}

func TestPlan_NotInstalled(t *testing.T) {
	m := aide.New()
	inspect := &testhelpers.FakeInspector{}
	action, err := m.Plan(context.Background(), &model.Finding{ID: "FINT-4350"}, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.True(t, action.Applicable)
}

func TestApplyAndValidate(t *testing.T) {
	m := aide.New()
	exec := &testhelpers.FakeExecutor{
		FakeInspector: testhelpers.FakeInspector{
			Files: map[string][]byte{},
		},
	}
	action := &model.PlannedAction{FindingID: "FINT-4350", ModuleID: "pkgs-aide", Applicable: true}

	applied, err := m.Apply(context.Background(), action, exec)
	require.NoError(t, err)
	assert.Equal(t, model.ActionApplied, applied.Status)
	assert.True(t, exec.PackageInstalled("aide"))

	// Simulate aideinit having created the DB file
	exec.Files[aide.DBPath] = []byte("aide-db")
	err = m.Validate(context.Background(), action, exec)
	assert.NoError(t, err)
}
