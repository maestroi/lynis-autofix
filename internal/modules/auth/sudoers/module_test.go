package sudoers_test

import (
	"context"
	"testing"

	"github.com/maestroi/hardener/internal/executor"
	"github.com/maestroi/hardener/internal/model"
	"github.com/maestroi/hardener/internal/modules/auth/sudoers"
	"github.com/maestroi/hardener/internal/testhelpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const sudoersPath = "/etc/sudoers"

// fakeInspectorWithStat wraps FakeInspector and returns a configurable stat output.
type fakeInspectorWithStat struct {
	testhelpers.FakeInspector
	StatOutput string
	StatErr    error
}

func (f *fakeInspectorWithStat) RunReadOnly(_ context.Context, name string, args ...string) (executor.CmdOutput, error) {
	if name == "stat" && f.StatErr == nil {
		return executor.CmdOutput{Stdout: f.StatOutput}, nil
	}
	return executor.CmdOutput{}, f.StatErr
}

func TestSudoers_Metadata(t *testing.T) {
	m := sudoers.New()
	meta := m.Metadata()
	assert.Equal(t, "auth-sudoers-perms", meta.ID)
	assert.Equal(t, model.RiskLow, meta.DefaultRisk)
	assert.True(t, meta.CanRollback)
}

func TestSudoers_Plan_AlreadyRestrictive_NotApplicable(t *testing.T) {
	inspect := &fakeInspectorWithStat{StatOutput: "440\n"}
	m := sudoers.New()
	finding := &model.Finding{ID: "AUTH-9282", Category: "AUTH"}

	action, err := m.Plan(context.Background(), finding, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.False(t, action.Applicable)
	assert.NotEmpty(t, action.SkipReason)
}

func TestSudoers_Plan_TooPermissive_Applicable(t *testing.T) {
	inspect := &fakeInspectorWithStat{StatOutput: "644\n"}
	m := sudoers.New()
	finding := &model.Finding{ID: "AUTH-9282", Category: "AUTH"}

	action, err := m.Plan(context.Background(), finding, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.True(t, action.Applicable)
	assert.Equal(t, "0644", action.Metadata["current_mode"])
	assert.Equal(t, "0440", action.Metadata["required_mode"])
}

func TestSudoers_Plan_400_NotApplicable(t *testing.T) {
	// 0400 is more restrictive than 0440 — not applicable.
	inspect := &fakeInspectorWithStat{StatOutput: "400\n"}
	m := sudoers.New()
	finding := &model.Finding{ID: "AUTH-9282", Category: "AUTH"}

	action, err := m.Plan(context.Background(), finding, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.False(t, action.Applicable)
}

func TestSudoers_Apply_SetsMode(t *testing.T) {
	exec := &testhelpers.FakeExecutor{}
	m := sudoers.New()
	action := &model.PlannedAction{
		FindingID: "AUTH-9282",
		ModuleID:  "auth-sudoers-perms",
		Metadata:  map[string]string{"target_file": sudoersPath},
	}

	applied, err := m.Apply(context.Background(), action, exec)
	require.NoError(t, err)
	assert.Equal(t, model.ActionApplied, applied.Status)
	// FakeExecutor.SetFileMode is a no-op — just confirm no error was returned.
}

func TestSudoers_Validate_CorrectMode_NoError(t *testing.T) {
	inspect := &fakeInspectorWithStat{StatOutput: "440\n"}
	m := sudoers.New()
	err := m.Validate(context.Background(), &model.PlannedAction{}, inspect)
	assert.NoError(t, err)
}

func TestSudoers_Validate_WrongMode_Error(t *testing.T) {
	inspect := &fakeInspectorWithStat{StatOutput: "644\n"}
	m := sudoers.New()
	err := m.Validate(context.Background(), &model.PlannedAction{}, inspect)
	assert.Error(t, err)
}

func TestSudoers_Rollback_RestoresFile(t *testing.T) {
	original := []byte("root ALL=(ALL:ALL) ALL\n")
	exec := &testhelpers.FakeExecutor{
		FakeInspector: testhelpers.FakeInspector{
			Files: map[string][]byte{"/backups/sudoers.bak": original},
		},
	}
	m := sudoers.New()
	entry := &model.RollbackEntry{
		Kind:       model.RollbackFile,
		Path:       sudoersPath,
		BackupPath: "/backups/sudoers.bak",
		OrigMode:   0o440,
	}
	err := m.Rollback(context.Background(), entry, exec)
	require.NoError(t, err)
	assert.True(t, exec.HasWritten(sudoersPath))
}

func TestSudoers_Rollback_UnexpectedKind_Error(t *testing.T) {
	exec := &testhelpers.FakeExecutor{}
	m := sudoers.New()
	entry := &model.RollbackEntry{Kind: model.RollbackPackage}
	err := m.Rollback(context.Background(), entry, exec)
	assert.Error(t, err)
}
