package debpurge_test

import (
	"context"
	"testing"

	"github.com/maestroi/hardener/internal/executor"
	"github.com/maestroi/hardener/internal/model"
	"github.com/maestroi/hardener/internal/modules/packages/debpurge"
	"github.com/maestroi/hardener/internal/testhelpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPlan_NothingToPurge(t *testing.T) {
	m := debpurge.New()
	inspect := &testhelpers.FakeInspector{
		RunReadOnlyFn: func(name string, args ...string) (executor.CmdOutput, error) {
			return executor.CmdOutput{Stdout: ""}, nil
		},
	}
	action, err := m.Plan(context.Background(), &model.Finding{ID: "DEB-0810"}, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.False(t, action.Applicable)
	assert.NotEmpty(t, action.SkipReason)
}

func TestPlan_HasRcPackages(t *testing.T) {
	m := debpurge.New()
	dpkgOutput := "rc  old-package  1.0  all  An old package\nrc  another-pkg  2.0  amd64  Another\n"
	inspect := &testhelpers.FakeInspector{
		RunReadOnlyFn: func(name string, args ...string) (executor.CmdOutput, error) {
			return executor.CmdOutput{Stdout: dpkgOutput}, nil
		},
	}
	action, err := m.Plan(context.Background(), &model.Finding{ID: "DEB-0810"}, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.True(t, action.Applicable)
	assert.Contains(t, action.Metadata["rc_packages"], "old-package")
	assert.Contains(t, action.Metadata["rc_packages"], "another-pkg")
}

func TestApply_PurgesPackages(t *testing.T) {
	m := debpurge.New()
	exec := &testhelpers.FakeExecutor{
		RunFn: func(name string, args ...string) (executor.CmdOutput, error) {
			return executor.CmdOutput{}, nil
		},
	}
	action := &model.PlannedAction{
		FindingID:  "DEB-0810",
		ModuleID:   "pkgs-debpurge",
		Applicable: true,
		Metadata:   map[string]string{"rc_packages": "old-package,another-pkg"},
	}
	applied, err := m.Apply(context.Background(), action, exec)
	require.NoError(t, err)
	assert.Equal(t, model.ActionApplied, applied.Status)
}
