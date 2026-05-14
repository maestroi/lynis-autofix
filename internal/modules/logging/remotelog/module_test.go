package remotelog_test

import (
	"context"
	"testing"

	"github.com/maestroi/hardener/internal/model"
	"github.com/maestroi/hardener/internal/modules/logging/remotelog"
	"github.com/maestroi/hardener/internal/testhelpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPlan_NoProfileConfig(t *testing.T) {
	m := remotelog.New()
	inspect := &testhelpers.FakeInspector{}
	action, err := m.Plan(context.Background(), &model.Finding{ID: "LOGG-2190"}, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.False(t, action.Applicable)
	assert.Contains(t, action.SkipReason, "remote_syslog_server")
}

func TestPlan_AlreadyConfigured(t *testing.T) {
	m := remotelog.New()
	profile := &model.Profile{RemoteSyslogServer: "10.0.0.1:514"}
	inspect := &testhelpers.FakeInspector{
		Files: map[string][]byte{
			remotelog.ConfPath: []byte("*.* @@10.0.0.1:514"),
		},
	}
	action, err := m.Plan(context.Background(), &model.Finding{ID: "LOGG-2190"}, profile, inspect)
	require.NoError(t, err)
	assert.False(t, action.Applicable)
}

func TestPlan_NeedsConfig(t *testing.T) {
	m := remotelog.New()
	profile := &model.Profile{RemoteSyslogServer: "10.0.0.1:514"}
	inspect := &testhelpers.FakeInspector{}
	action, err := m.Plan(context.Background(), &model.Finding{ID: "LOGG-2190"}, profile, inspect)
	require.NoError(t, err)
	assert.True(t, action.Applicable)
	assert.Equal(t, model.RiskMedium, action.Risk)
}

func TestApplyAndValidate(t *testing.T) {
	m := remotelog.New()
	exec := &testhelpers.FakeExecutor{}
	profile := &model.Profile{RemoteSyslogServer: "10.0.0.1:514"}
	action := &model.PlannedAction{
		FindingID:  "LOGG-2190",
		ModuleID:   "logging-remotelog",
		Applicable: true,
		Metadata:   map[string]string{"server": "10.0.0.1:514"},
	}

	applied, err := m.Apply(context.Background(), action, exec)
	require.NoError(t, err)
	assert.Equal(t, model.ActionApplied, applied.Status)
	assert.True(t, exec.FileContains(remotelog.ConfPath, "10.0.0.1:514"))
	_ = profile

	err = m.Validate(context.Background(), action, exec)
	assert.NoError(t, err)
}
