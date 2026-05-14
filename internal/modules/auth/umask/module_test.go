package umask_test

import (
	"context"
	"testing"

	"github.com/maestroi/hardener/internal/model"
	"github.com/maestroi/hardener/internal/modules/auth/umask"
	"github.com/maestroi/hardener/internal/testhelpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const loginDefs = "/etc/login.defs"

func TestUmask_Metadata(t *testing.T) {
	m := umask.New()
	meta := m.Metadata()
	assert.Equal(t, "auth-umask", meta.ID)
	assert.True(t, meta.CanRollback)
}

func TestUmask_Plan_AlreadyCorrect_NotApplicable(t *testing.T) {
	content := []byte("UMASK\t\t027\n")
	inspect := &testhelpers.FakeInspector{
		Files: map[string][]byte{loginDefs: content},
	}
	m := umask.New()
	finding := &model.Finding{ID: "AUTH-9328", Category: "AUTH"}

	action, err := m.Plan(context.Background(), finding, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.False(t, action.Applicable)
	assert.NotEmpty(t, action.SkipReason)
}

func TestUmask_Plan_WrongUmask_Applicable(t *testing.T) {
	content := []byte("UMASK\t\t022\n")
	inspect := &testhelpers.FakeInspector{
		Files: map[string][]byte{loginDefs: content},
	}
	m := umask.New()
	finding := &model.Finding{ID: "AUTH-9328", Category: "AUTH"}

	action, err := m.Plan(context.Background(), finding, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.True(t, action.Applicable)
}

func TestUmask_Plan_MissingUmask_Applicable(t *testing.T) {
	content := []byte("PASS_MAX_DAYS\t90\n")
	inspect := &testhelpers.FakeInspector{
		Files: map[string][]byte{loginDefs: content},
	}
	m := umask.New()
	finding := &model.Finding{ID: "AUTH-9328", Category: "AUTH"}

	action, err := m.Plan(context.Background(), finding, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.True(t, action.Applicable)
}

func TestUmask_Apply_ReplacesExistingLine(t *testing.T) {
	content := []byte("PASS_MAX_DAYS\t90\nUMASK\t\t022\n")
	exec := &testhelpers.FakeExecutor{
		FakeInspector: testhelpers.FakeInspector{
			Files: map[string][]byte{loginDefs: content},
		},
	}
	m := umask.New()
	action := &model.PlannedAction{
		FindingID: "AUTH-9328",
		ModuleID:  "auth-umask",
		Metadata:  map[string]string{"target_file": loginDefs},
	}

	applied, err := m.Apply(context.Background(), action, exec)
	require.NoError(t, err)
	assert.Equal(t, model.ActionApplied, applied.Status)
	assert.True(t, exec.FileContains(loginDefs, "027"))
}

func TestUmask_Apply_AppendsMissingLine(t *testing.T) {
	content := []byte("PASS_MAX_DAYS\t90\n")
	exec := &testhelpers.FakeExecutor{
		FakeInspector: testhelpers.FakeInspector{
			Files: map[string][]byte{loginDefs: content},
		},
	}
	m := umask.New()
	action := &model.PlannedAction{
		FindingID: "AUTH-9328",
		ModuleID:  "auth-umask",
		Metadata:  map[string]string{"target_file": loginDefs},
	}

	applied, err := m.Apply(context.Background(), action, exec)
	require.NoError(t, err)
	assert.Equal(t, model.ActionApplied, applied.Status)
	assert.True(t, exec.FileContains(loginDefs, "027"))
}

func TestUmask_Validate_Correct_NoError(t *testing.T) {
	inspect := &testhelpers.FakeInspector{
		Files: map[string][]byte{loginDefs: []byte("UMASK\t\t027\n")},
	}
	m := umask.New()
	err := m.Validate(context.Background(), &model.PlannedAction{}, inspect)
	assert.NoError(t, err)
}

func TestUmask_Validate_Wrong_Error(t *testing.T) {
	inspect := &testhelpers.FakeInspector{
		Files: map[string][]byte{loginDefs: []byte("UMASK\t\t022\n")},
	}
	m := umask.New()
	err := m.Validate(context.Background(), &model.PlannedAction{}, inspect)
	assert.Error(t, err)
}

func TestUmask_Rollback_RestoresFile(t *testing.T) {
	original := []byte("UMASK\t\t022\n")
	exec := &testhelpers.FakeExecutor{
		FakeInspector: testhelpers.FakeInspector{
			Files: map[string][]byte{"/backups/login.defs.bak": original},
		},
	}
	m := umask.New()
	entry := &model.RollbackEntry{
		Kind:       model.RollbackFile,
		Path:       loginDefs,
		BackupPath: "/backups/login.defs.bak",
		OrigMode:   0o644,
	}
	err := m.Rollback(context.Background(), entry, exec)
	require.NoError(t, err)
	assert.True(t, exec.HasWritten(loginDefs))
}
