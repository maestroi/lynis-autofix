package pamhistory_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/maestroi/hardener/internal/model"
	"github.com/maestroi/hardener/internal/modules/auth/pamhistory"
	"github.com/maestroi/hardener/internal/testhelpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const commonPassword = "/etc/pam.d/common-password"

func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("../../../../testdata/auth", name))
	require.NoError(t, err)
	return data
}

func TestPAMHistory_Metadata(t *testing.T) {
	m := pamhistory.New()
	meta := m.Metadata()
	assert.Equal(t, "auth-pam-history", meta.ID)
	assert.Equal(t, model.RiskMedium, meta.DefaultRisk)
	assert.True(t, meta.CanRollback)
}

func TestPAMHistory_Plan_AlreadyHardened_NotApplicable(t *testing.T) {
	content := loadFixture(t, "common-password_hardened")
	inspect := &testhelpers.FakeInspector{
		Files: map[string][]byte{commonPassword: content},
	}
	m := pamhistory.New()
	finding := &model.Finding{ID: "AUTH-9229", Category: "AUTH"}

	action, err := m.Plan(context.Background(), finding, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.False(t, action.Applicable)
	assert.NotEmpty(t, action.SkipReason)
}

func TestPAMHistory_Plan_Default_Applicable(t *testing.T) {
	content := loadFixture(t, "common-password_default")
	inspect := &testhelpers.FakeInspector{
		Files: map[string][]byte{commonPassword: content},
	}
	m := pamhistory.New()
	finding := &model.Finding{ID: "AUTH-9229", Category: "AUTH"}

	action, err := m.Plan(context.Background(), finding, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.True(t, action.Applicable)
	assert.Equal(t, model.RiskMedium, action.Risk)
}

func TestPAMHistory_Plan_RememberTooLow_Applicable(t *testing.T) {
	content := []byte("password\t[success=1 default=ignore]\tpam_unix.so obscure sha512 remember=3\n")
	inspect := &testhelpers.FakeInspector{
		Files: map[string][]byte{commonPassword: content},
	}
	m := pamhistory.New()
	finding := &model.Finding{ID: "AUTH-9229", Category: "AUTH"}

	action, err := m.Plan(context.Background(), finding, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.True(t, action.Applicable)
}

func TestPAMHistory_Plan_RememberHighEnough_NotApplicable(t *testing.T) {
	content := []byte("password\t[success=1 default=ignore]\tpam_unix.so obscure sha512 remember=10\n")
	inspect := &testhelpers.FakeInspector{
		Files: map[string][]byte{commonPassword: content},
	}
	m := pamhistory.New()
	finding := &model.Finding{ID: "AUTH-9229", Category: "AUTH"}

	action, err := m.Plan(context.Background(), finding, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.False(t, action.Applicable)
}

func TestPAMHistory_Apply_AddsRemember(t *testing.T) {
	content := loadFixture(t, "common-password_default")
	exec := &testhelpers.FakeExecutor{
		FakeInspector: testhelpers.FakeInspector{
			Files: map[string][]byte{commonPassword: content},
		},
	}
	m := pamhistory.New()
	action := &model.PlannedAction{
		FindingID: "AUTH-9229",
		ModuleID:  "auth-pam-history",
		Metadata:  map[string]string{"target_file": commonPassword},
	}

	applied, err := m.Apply(context.Background(), action, exec)
	require.NoError(t, err)
	assert.Equal(t, model.ActionApplied, applied.Status)
	assert.True(t, exec.FileContains(commonPassword, "remember=5"))
}

func TestPAMHistory_Validate_Hardened_NoError(t *testing.T) {
	content := loadFixture(t, "common-password_hardened")
	inspect := &testhelpers.FakeInspector{
		Files: map[string][]byte{commonPassword: content},
	}
	m := pamhistory.New()
	err := m.Validate(context.Background(), &model.PlannedAction{}, inspect)
	assert.NoError(t, err)
}

func TestPAMHistory_Validate_Default_Error(t *testing.T) {
	content := loadFixture(t, "common-password_default")
	inspect := &testhelpers.FakeInspector{
		Files: map[string][]byte{commonPassword: content},
	}
	m := pamhistory.New()
	err := m.Validate(context.Background(), &model.PlannedAction{}, inspect)
	assert.Error(t, err)
}

func TestPAMHistory_Rollback_RestoresFile(t *testing.T) {
	original := loadFixture(t, "common-password_default")
	exec := &testhelpers.FakeExecutor{
		FakeInspector: testhelpers.FakeInspector{
			Files: map[string][]byte{"/backups/common-password.bak": original},
		},
	}
	m := pamhistory.New()
	entry := &model.RollbackEntry{
		Kind:       model.RollbackFile,
		Path:       commonPassword,
		BackupPath: "/backups/common-password.bak",
		OrigMode:   0o644,
	}
	err := m.Rollback(context.Background(), entry, exec)
	require.NoError(t, err)
	assert.True(t, exec.HasWritten(commonPassword))
}
