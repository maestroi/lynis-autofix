package protocols_test

import (
	"context"
	"testing"

	"github.com/maestroi/hardener/internal/model"
	"github.com/maestroi/hardener/internal/modules/kernel/protocols"
	"github.com/maestroi/hardener/internal/testhelpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPlan_AlreadyDisabled(t *testing.T) {
	m := protocols.New()
	inspect := &testhelpers.FakeInspector{
		Files: map[string][]byte{protocols.ConfPath: []byte(protocols.ConfContent)},
	}
	action, err := m.Plan(context.Background(), &model.Finding{ID: "NETW-3200"}, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.False(t, action.Applicable)
}

func TestPlan_NotPresent(t *testing.T) {
	m := protocols.New()
	inspect := &testhelpers.FakeInspector{}
	action, err := m.Plan(context.Background(), &model.Finding{ID: "NETW-3200"}, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.True(t, action.Applicable)
}

func TestApplyAndValidate(t *testing.T) {
	m := protocols.New()
	exec := &testhelpers.FakeExecutor{}
	action := &model.PlannedAction{FindingID: "NETW-3200", ModuleID: "kernel-protocols", Applicable: true}

	applied, err := m.Apply(context.Background(), action, exec)
	require.NoError(t, err)
	assert.Equal(t, model.ActionApplied, applied.Status)
	assert.True(t, exec.FileContains(protocols.ConfPath, "install dccp /bin/true"))
	assert.True(t, exec.FileContains(protocols.ConfPath, "install tipc /bin/true"))

	err = m.Validate(context.Background(), action, exec)
	assert.NoError(t, err)
}
