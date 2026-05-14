package banner_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/maestroi/hardener/internal/model"
	bannermod "github.com/maestroi/hardener/internal/modules/banner"
	"github.com/maestroi/hardener/internal/testhelpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func loadBannerFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("../../../testdata/banner", name))
	require.NoError(t, err)
	return data
}

func TestBanner_Metadata(t *testing.T) {
	m := bannermod.New()
	meta := m.Metadata()
	assert.Equal(t, "banner-legal", meta.ID)
	assert.Contains(t, meta.SupportedDistros, "ubuntu")
	assert.True(t, meta.CanRollback)
}

func TestBanner_SupportedFindings(t *testing.T) {
	findings := bannermod.New().SupportedFindings()
	assert.Contains(t, findings, "BANN-7126")
	assert.Contains(t, findings, "BANN-7130")
}

func TestBanner_Plan_BANN7126_EmptyIssue_Applicable(t *testing.T) {
	content := loadBannerFixture(t, "issue_empty")
	inspect := &testhelpers.FakeInspector{
		Files: map[string][]byte{bannermod.IssuePath: content},
	}
	m := bannermod.New()
	action, err := m.Plan(context.Background(), &model.Finding{ID: "BANN-7126"}, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.True(t, action.Applicable)
	assert.Contains(t, action.Metadata, "target_file")
	assert.Equal(t, bannermod.IssuePath, action.Metadata["target_file"])
}

func TestBanner_Plan_BANN7130_EmptyIssueNet_Applicable(t *testing.T) {
	inspect := &testhelpers.FakeInspector{
		Files: map[string][]byte{bannermod.IssueNetPath: []byte("")},
	}
	m := bannermod.New()
	action, err := m.Plan(context.Background(), &model.Finding{ID: "BANN-7130"}, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.True(t, action.Applicable)
	assert.Equal(t, bannermod.IssueNetPath, action.Metadata["target_file"])
}

func TestBanner_Plan_AlreadySet_NotApplicable(t *testing.T) {
	content := loadBannerFixture(t, "issue_set")
	inspect := &testhelpers.FakeInspector{
		Files: map[string][]byte{bannermod.IssuePath: content},
	}
	m := bannermod.New()
	action, err := m.Plan(context.Background(), &model.Finding{ID: "BANN-7126"}, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.False(t, action.Applicable)
	assert.NotEmpty(t, action.SkipReason)
}

func TestBanner_Plan_FileMissing_Applicable(t *testing.T) {
	inspect := &testhelpers.FakeInspector{Files: map[string][]byte{}}
	m := bannermod.New()
	action, err := m.Plan(context.Background(), &model.Finding{ID: "BANN-7126"}, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.True(t, action.Applicable)
}

func TestBanner_Apply_WritesLegalBanner(t *testing.T) {
	exec := &testhelpers.FakeExecutor{
		FakeInspector: testhelpers.FakeInspector{
			Files: map[string][]byte{bannermod.IssuePath: []byte("Ubuntu 22.04")},
		},
	}
	m := bannermod.New()
	action := &model.PlannedAction{
		FindingID: "BANN-7126",
		ModuleID:  "banner-legal",
		Metadata:  map[string]string{"target_file": bannermod.IssuePath},
	}

	applied, err := m.Apply(context.Background(), action, exec)
	require.NoError(t, err)
	assert.Equal(t, model.ActionApplied, applied.Status)
	assert.True(t, exec.HasWritten(bannermod.IssuePath))
	assert.True(t, exec.FileContains(bannermod.IssuePath, "AUTHORIZED ACCESS ONLY"))
}

func TestBanner_Validate_BannerPresent_NoError(t *testing.T) {
	content := loadBannerFixture(t, "issue_set")
	inspect := &testhelpers.FakeInspector{
		Files: map[string][]byte{bannermod.IssuePath: content},
	}
	m := bannermod.New()
	err := m.Validate(context.Background(), &model.PlannedAction{
		FindingID: "BANN-7126",
		Metadata:  map[string]string{"target_file": bannermod.IssuePath},
	}, inspect)
	assert.NoError(t, err)
}

func TestBanner_Rollback_RestoresFile(t *testing.T) {
	originalContent := []byte("Ubuntu 22.04")
	exec := &testhelpers.FakeExecutor{
		FakeInspector: testhelpers.FakeInspector{
			Files: map[string][]byte{"/tmp/backup": originalContent},
		},
	}
	m := bannermod.New()
	entry := &model.RollbackEntry{
		Kind:       model.RollbackFile,
		Path:       bannermod.IssuePath,
		BackupPath: "/tmp/backup",
		OrigMode:   0644,
	}
	err := m.Rollback(context.Background(), entry, exec)
	require.NoError(t, err)
	assert.True(t, exec.HasWritten(bannermod.IssuePath))
}
