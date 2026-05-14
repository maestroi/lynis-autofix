package modules_test

import (
	"context"
	"testing"

	"github.com/maestroi/hardener/internal/model"
	kernelmodules "github.com/maestroi/hardener/internal/modules/kernel/modules"
	"github.com/maestroi/hardener/internal/testhelpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPlan_AlreadyDisabled(t *testing.T) {
	m := kernelmodules.New()
	inspect := &testhelpers.FakeInspector{
		SysctlValues: map[string]string{"kernel.modules_disabled": "1"},
	}
	action, err := m.Plan(context.Background(), &model.Finding{ID: "KRNL-5830"}, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.False(t, action.Applicable)
}

func TestPlan_NotDisabled(t *testing.T) {
	m := kernelmodules.New()
	inspect := &testhelpers.FakeInspector{
		SysctlValues: map[string]string{"kernel.modules_disabled": "0"},
	}
	action, err := m.Plan(context.Background(), &model.Finding{ID: "KRNL-5830"}, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.True(t, action.Applicable)
	assert.True(t, action.Dangerous)
	assert.Equal(t, model.RiskCritical, action.Risk)
}

func TestApplyAndValidate(t *testing.T) {
	m := kernelmodules.New()
	exec := &testhelpers.FakeExecutor{
		FakeInspector: testhelpers.FakeInspector{
			SysctlValues: map[string]string{"kernel.modules_disabled": "1"},
		},
	}
	action := &model.PlannedAction{
		FindingID:  "KRNL-5830",
		ModuleID:   "kernel-modules-disabled",
		Applicable: true,
		Dangerous:  true,
	}

	applied, err := m.Apply(context.Background(), action, exec)
	require.NoError(t, err)
	assert.Equal(t, model.ActionApplied, applied.Status)
	assert.True(t, exec.HasWritten(kernelmodules.ConfPath))

	err = m.Validate(context.Background(), action, exec)
	assert.NoError(t, err)
}
