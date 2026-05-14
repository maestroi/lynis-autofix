package passwordaging_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/maestroi/hardener/internal/model"
	"github.com/maestroi/hardener/internal/modules/auth/passwordaging"
	"github.com/maestroi/hardener/internal/testhelpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const loginDefs = "/etc/login.defs"

func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("../../../../testdata/auth", name))
	require.NoError(t, err)
	return data
}

func TestPasswordAging_Metadata(t *testing.T) {
	m := passwordaging.New()
	meta := m.Metadata()
	assert.Equal(t, "auth-password-aging", meta.ID)
	assert.True(t, meta.CanRollback)
}

func TestPasswordAging_Plan_AlreadyHardened_NotApplicable(t *testing.T) {
	content := loadFixture(t, "login.defs_hardened")
	inspect := &testhelpers.FakeInspector{
		Files: map[string][]byte{loginDefs: content},
	}
	m := passwordaging.New()
	finding := &model.Finding{ID: "AUTH-9286", Category: "AUTH"}

	action, err := m.Plan(context.Background(), finding, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.False(t, action.Applicable)
	assert.NotEmpty(t, action.SkipReason)
}

func TestPasswordAging_Plan_Default_Applicable(t *testing.T) {
	content := loadFixture(t, "login.defs_default")
	inspect := &testhelpers.FakeInspector{
		Files: map[string][]byte{loginDefs: content},
	}
	m := passwordaging.New()
	finding := &model.Finding{ID: "AUTH-9286", Category: "AUTH"}

	action, err := m.Plan(context.Background(), finding, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.True(t, action.Applicable)
	assert.NotEmpty(t, action.Steps)
	assert.Equal(t, loginDefs, action.Metadata["target_file"])
}

func TestPasswordAging_Apply_WritesHardenedValues(t *testing.T) {
	content := loadFixture(t, "login.defs_default")
	exec := &testhelpers.FakeExecutor{
		FakeInspector: testhelpers.FakeInspector{
			Files: map[string][]byte{loginDefs: content},
		},
	}
	m := passwordaging.New()
	action := &model.PlannedAction{
		FindingID: "AUTH-9286",
		ModuleID:  "auth-password-aging",
		Metadata:  map[string]string{"target_file": loginDefs},
	}

	applied, err := m.Apply(context.Background(), action, exec)
	require.NoError(t, err)
	assert.Equal(t, model.ActionApplied, applied.Status)
	assert.True(t, exec.HasWritten(loginDefs))
	assert.True(t, exec.FileContains(loginDefs, "PASS_MAX_DAYS\t90"))
	assert.True(t, exec.FileContains(loginDefs, "PASS_MIN_DAYS\t1"))
	assert.True(t, exec.FileContains(loginDefs, "PASS_WARN_AGE\t14"))
}

func TestPasswordAging_Validate_HardenedContent_NoError(t *testing.T) {
	content := loadFixture(t, "login.defs_hardened")
	inspect := &testhelpers.FakeInspector{
		Files: map[string][]byte{loginDefs: content},
	}
	m := passwordaging.New()
	err := m.Validate(context.Background(), &model.PlannedAction{}, inspect)
	assert.NoError(t, err)
}

func TestPasswordAging_Validate_DefaultContent_Error(t *testing.T) {
	content := loadFixture(t, "login.defs_default")
	inspect := &testhelpers.FakeInspector{
		Files: map[string][]byte{loginDefs: content},
	}
	m := passwordaging.New()
	err := m.Validate(context.Background(), &model.PlannedAction{}, inspect)
	assert.Error(t, err)
}

func TestPasswordAging_Rollback_RestoresFile(t *testing.T) {
	original := []byte("PASS_MAX_DAYS   99999\n")
	exec := &testhelpers.FakeExecutor{
		FakeInspector: testhelpers.FakeInspector{
			Files: map[string][]byte{"/backups/login.defs.bak": original},
		},
	}
	m := passwordaging.New()
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

func TestPasswordAging_Rollback_UnexpectedKind_Error(t *testing.T) {
	exec := &testhelpers.FakeExecutor{}
	m := passwordaging.New()
	entry := &model.RollbackEntry{Kind: model.RollbackPackage}
	err := m.Rollback(context.Background(), entry, exec)
	assert.Error(t, err)
}
