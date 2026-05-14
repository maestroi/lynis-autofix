package pamfaillock_test

import (
	"context"
	"testing"

	"github.com/maestroi/hardener/internal/model"
	"github.com/maestroi/hardener/internal/modules/auth/pamfaillock"
	"github.com/maestroi/hardener/internal/testhelpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const faillockConf = "/etc/security/faillock.conf"

func TestFaillock_Metadata(t *testing.T) {
	m := pamfaillock.New()
	meta := m.Metadata()
	assert.Equal(t, "auth-pam-faillock", meta.ID)
	assert.Equal(t, model.RiskMedium, meta.DefaultRisk)
	assert.True(t, meta.CanRollback)
}

func TestFaillock_Plan_AlreadyConfigured_NotApplicable(t *testing.T) {
	content := []byte("deny = 5\nunlock_time = 900\nsilent\n")
	inspect := &testhelpers.FakeInspector{
		Files: map[string][]byte{faillockConf: content},
	}
	m := pamfaillock.New()
	finding := &model.Finding{ID: "AUTH-9230", Category: "AUTH"}

	action, err := m.Plan(context.Background(), finding, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.False(t, action.Applicable)
	assert.NotEmpty(t, action.SkipReason)
}

func TestFaillock_Plan_MissingConf_Applicable(t *testing.T) {
	inspect := &testhelpers.FakeInspector{Files: map[string][]byte{}}
	m := pamfaillock.New()
	finding := &model.Finding{ID: "AUTH-9230", Category: "AUTH"}

	action, err := m.Plan(context.Background(), finding, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.True(t, action.Applicable)
}

func TestFaillock_Plan_NoPAMEntry_SetsManualPAMFlag(t *testing.T) {
	inspect := &testhelpers.FakeInspector{Files: map[string][]byte{}}
	m := pamfaillock.New()
	finding := &model.Finding{ID: "AUTH-9230", Category: "AUTH"}

	action, err := m.Plan(context.Background(), finding, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.Equal(t, "true", action.Metadata["manual_pam"])
}

func TestFaillock_Plan_PAMEntryPresent_NoManualFlag(t *testing.T) {
	inspect := &testhelpers.FakeInspector{
		Files: map[string][]byte{
			"/etc/pam.d/common-auth": []byte("auth required pam_faillock.so\n"),
		},
	}
	m := pamfaillock.New()
	finding := &model.Finding{ID: "AUTH-9230", Category: "AUTH"}

	action, err := m.Plan(context.Background(), finding, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.NotEqual(t, "true", action.Metadata["manual_pam"])
}

func TestFaillock_Apply_WritesPolicyValues(t *testing.T) {
	exec := &testhelpers.FakeExecutor{
		FakeInspector: testhelpers.FakeInspector{Files: map[string][]byte{}},
	}
	m := pamfaillock.New()
	action := &model.PlannedAction{
		FindingID: "AUTH-9230",
		ModuleID:  "auth-pam-faillock",
		Metadata:  map[string]string{"target_file": faillockConf},
	}

	applied, err := m.Apply(context.Background(), action, exec)
	require.NoError(t, err)
	assert.Equal(t, model.ActionApplied, applied.Status)
	assert.True(t, exec.FileContains(faillockConf, "deny = 5"))
	assert.True(t, exec.FileContains(faillockConf, "unlock_time = 900"))
	assert.True(t, exec.FileContains(faillockConf, "silent"))
}

func TestFaillock_Apply_DoesNotWriteCommonAuth(t *testing.T) {
	exec := &testhelpers.FakeExecutor{
		FakeInspector: testhelpers.FakeInspector{Files: map[string][]byte{}},
	}
	m := pamfaillock.New()
	action := &model.PlannedAction{FindingID: "AUTH-9230", ModuleID: "auth-pam-faillock"}

	_, err := m.Apply(context.Background(), action, exec)
	require.NoError(t, err)
	assert.False(t, exec.HasWritten("/etc/pam.d/common-auth"),
		"Apply must never modify common-auth automatically")
}

func TestFaillock_Validate_Correct_NoError(t *testing.T) {
	content := []byte("deny = 5\nunlock_time = 900\n")
	inspect := &testhelpers.FakeInspector{
		Files: map[string][]byte{faillockConf: content},
	}
	m := pamfaillock.New()
	err := m.Validate(context.Background(), &model.PlannedAction{}, inspect)
	assert.NoError(t, err)
}

func TestFaillock_Validate_Wrong_Error(t *testing.T) {
	content := []byte("deny = 3\nunlock_time = 600\n")
	inspect := &testhelpers.FakeInspector{
		Files: map[string][]byte{faillockConf: content},
	}
	m := pamfaillock.New()
	err := m.Validate(context.Background(), &model.PlannedAction{}, inspect)
	assert.Error(t, err)
}

func TestFaillock_Rollback_RestoresFile(t *testing.T) {
	original := []byte("# empty\n")
	exec := &testhelpers.FakeExecutor{
		FakeInspector: testhelpers.FakeInspector{
			Files: map[string][]byte{"/backups/faillock.conf.bak": original},
		},
	}
	m := pamfaillock.New()
	entry := &model.RollbackEntry{
		Kind:       model.RollbackFile,
		Path:       faillockConf,
		BackupPath: "/backups/faillock.conf.bak",
		OrigMode:   0o644,
	}
	err := m.Rollback(context.Background(), entry, exec)
	require.NoError(t, err)
	assert.True(t, exec.HasWritten(faillockConf))
}
