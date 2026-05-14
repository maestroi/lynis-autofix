package firewall_test

import (
	"context"
	"testing"

	"github.com/maestroi/hardener/internal/executor"
	"github.com/maestroi/hardener/internal/model"
	"github.com/maestroi/hardener/internal/modules/network/firewall"
	"github.com/maestroi/hardener/internal/testhelpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPlan_AlreadyActive(t *testing.T) {
	m := firewall.New()
	inspect := &testhelpers.FakeInspector{
		InstalledPkgs: map[string]bool{"ufw": true},
		Services:      map[string]executor.ServiceStatus{"ufw": {Name: "ufw", Active: true, Enabled: true}},
	}
	action, err := m.Plan(context.Background(), &model.Finding{ID: "FIRE-4513"}, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.False(t, action.Applicable)
}

func TestPlan_NotPresent(t *testing.T) {
	m := firewall.New()
	inspect := &testhelpers.FakeInspector{}
	action, err := m.Plan(context.Background(), &model.Finding{ID: "FIRE-4513"}, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.True(t, action.Applicable)
	assert.Equal(t, model.RiskMedium, action.Risk)
}

func TestApplyAndValidate(t *testing.T) {
	m := firewall.New()
	exec := &testhelpers.FakeExecutor{}
	action := &model.PlannedAction{FindingID: "FIRE-4513", ModuleID: "network-firewall", Applicable: true}

	applied, err := m.Apply(context.Background(), action, exec)
	require.NoError(t, err)
	assert.Equal(t, model.ActionApplied, applied.Status)
	assert.True(t, exec.PackageInstalled("ufw"))

	err = m.Validate(context.Background(), action, exec)
	assert.NoError(t, err)
}
