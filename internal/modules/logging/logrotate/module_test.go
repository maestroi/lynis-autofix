package logrotate_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/maestroi/hardener/internal/model"
	logrotatemod "github.com/maestroi/hardener/internal/modules/logging/logrotate"
	"github.com/maestroi/hardener/internal/testhelpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("../../../../testdata/logrotate", name))
	require.NoError(t, err)
	return data
}

func TestLogrotate_Metadata(t *testing.T) {
	m := logrotatemod.New()
	meta := m.Metadata()
	assert.Equal(t, "logging-logrotate-compress", meta.ID)
	assert.Contains(t, meta.SupportedDistros, "ubuntu")
	assert.True(t, meta.CanRollback)
}

func TestLogrotate_SupportedFindings(t *testing.T) {
	assert.Contains(t, logrotatemod.New().SupportedFindings(), "LOGG-2154")
}

func TestLogrotate_Plan_CompressAlreadySet_NotApplicable(t *testing.T) {
	content := loadFixture(t, "logrotate.conf_compressed")
	inspect := &testhelpers.FakeInspector{
		Files: map[string][]byte{logrotatemod.ConfigPath: content},
	}
	m := logrotatemod.New()
	action, err := m.Plan(context.Background(), &model.Finding{ID: "LOGG-2154"}, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.False(t, action.Applicable)
	assert.NotEmpty(t, action.SkipReason)
}

func TestLogrotate_Plan_CompressMissing_Applicable(t *testing.T) {
	content := loadFixture(t, "logrotate.conf_default")
	inspect := &testhelpers.FakeInspector{
		Files: map[string][]byte{logrotatemod.ConfigPath: content},
	}
	m := logrotatemod.New()
	action, err := m.Plan(context.Background(), &model.Finding{ID: "LOGG-2154"}, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.True(t, action.Applicable)
	assert.Contains(t, action.Metadata, "target_file")
}

func TestLogrotate_Plan_FileNotFound_NotApplicable(t *testing.T) {
	inspect := &testhelpers.FakeInspector{Files: map[string][]byte{}}
	m := logrotatemod.New()
	action, err := m.Plan(context.Background(), &model.Finding{ID: "LOGG-2154"}, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.False(t, action.Applicable)
	assert.Contains(t, action.SkipReason, "not found")
}

func TestLogrotate_Apply_AddsCompress(t *testing.T) {
	content := loadFixture(t, "logrotate.conf_default")
	exec := &testhelpers.FakeExecutor{
		FakeInspector: testhelpers.FakeInspector{
			Files: map[string][]byte{logrotatemod.ConfigPath: content},
		},
	}
	m := logrotatemod.New()
	action := &model.PlannedAction{
		FindingID: "LOGG-2154",
		ModuleID:  "logging-logrotate-compress",
		Metadata:  map[string]string{"target_file": logrotatemod.ConfigPath},
	}

	applied, err := m.Apply(context.Background(), action, exec)
	require.NoError(t, err)
	assert.Equal(t, model.ActionApplied, applied.Status)
	assert.True(t, exec.HasWritten(logrotatemod.ConfigPath))
	assert.True(t, exec.FileContains(logrotatemod.ConfigPath, "\ncompress\n"))
}

func TestLogrotate_Validate_CompressPresent_NoError(t *testing.T) {
	content := loadFixture(t, "logrotate.conf_compressed")
	inspect := &testhelpers.FakeInspector{
		Files: map[string][]byte{logrotatemod.ConfigPath: content},
	}
	m := logrotatemod.New()
	err := m.Validate(context.Background(), &model.PlannedAction{
		FindingID: "LOGG-2154",
		Metadata:  map[string]string{"target_file": logrotatemod.ConfigPath},
	}, inspect)
	assert.NoError(t, err)
}

func TestLogrotate_Validate_CommentedCompress_Error(t *testing.T) {
	content := loadFixture(t, "logrotate.conf_default") // has #compress
	inspect := &testhelpers.FakeInspector{
		Files: map[string][]byte{logrotatemod.ConfigPath: content},
	}
	m := logrotatemod.New()
	err := m.Validate(context.Background(), &model.PlannedAction{
		FindingID: "LOGG-2154",
		Metadata:  map[string]string{"target_file": logrotatemod.ConfigPath},
	}, inspect)
	assert.Error(t, err)
}

func TestLogrotate_Rollback_RestoresFile(t *testing.T) {
	original := loadFixture(t, "logrotate.conf_default")
	exec := &testhelpers.FakeExecutor{
		FakeInspector: testhelpers.FakeInspector{
			Files: map[string][]byte{"/tmp/backup": original},
		},
	}
	m := logrotatemod.New()
	entry := &model.RollbackEntry{
		Kind:       model.RollbackFile,
		Path:       logrotatemod.ConfigPath,
		BackupPath: "/tmp/backup",
		OrigMode:   0644,
	}
	err := m.Rollback(context.Background(), entry, exec)
	require.NoError(t, err)
	assert.True(t, exec.HasWritten(logrotatemod.ConfigPath))
}
