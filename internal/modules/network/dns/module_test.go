package dns_test

import (
	"context"
	"testing"

	"github.com/maestroi/hardener/internal/executor"
	"github.com/maestroi/hardener/internal/model"
	"github.com/maestroi/hardener/internal/modules/network/dns"
	"github.com/maestroi/hardener/internal/testhelpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPlan_AlreadyEnabled(t *testing.T) {
	m := dns.New()
	inspect := &testhelpers.FakeInspector{
		Files: map[string][]byte{
			dns.ResolvedConfPath: []byte("[Resolve]\nDNSSEC=yes\n"),
		},
	}
	action, err := m.Plan(context.Background(), &model.Finding{ID: "NAME-4028"}, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.False(t, action.Applicable)
}

func TestPlan_NotConfigured(t *testing.T) {
	m := dns.New()
	inspect := &testhelpers.FakeInspector{
		Files: map[string][]byte{
			dns.ResolvedConfPath: []byte("[Resolve]\n#DNSSEC=no\n"),
		},
	}
	action, err := m.Plan(context.Background(), &model.Finding{ID: "NAME-4028"}, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.True(t, action.Applicable)
	assert.Equal(t, model.RiskMedium, action.Risk)
}

func TestApplyAndValidate(t *testing.T) {
	m := dns.New()
	exec := &testhelpers.FakeExecutor{
		FakeInspector: testhelpers.FakeInspector{
			Services: map[string]executor.ServiceStatus{
				"systemd-resolved": {Name: "systemd-resolved", Active: true, Enabled: true},
			},
		},
	}
	action := &model.PlannedAction{FindingID: "NAME-4028", ModuleID: "network-dns", Applicable: true}

	applied, err := m.Apply(context.Background(), action, exec)
	require.NoError(t, err)
	assert.Equal(t, model.ActionApplied, applied.Status)
	assert.True(t, exec.FileContains(dns.ResolvedConfPath, "DNSSEC=yes"))
	assert.True(t, testhelpers.ContainsService(exec.RestartedServices, "systemd-resolved"))

	err = m.Validate(context.Background(), action, exec)
	assert.NoError(t, err)
}
