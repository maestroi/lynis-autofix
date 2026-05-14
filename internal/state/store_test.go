package state_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/maestroi/hardener/internal/model"
	"github.com/maestroi/hardener/internal/state"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTempStore(t *testing.T) *state.FileStore {
	t.Helper()
	dir := t.TempDir()
	s, err := state.NewFileStore(dir)
	require.NoError(t, err)
	return s
}

func TestFileStore_InitRun_CreatesDirectory(t *testing.T) {
	s := newTempStore(t)
	run, err := s.InitRun(context.Background(), "server", false)
	require.NoError(t, err)
	assert.NotEmpty(t, run.ID)
	assert.Equal(t, "server", run.ProfileName)
	assert.Equal(t, model.RunPlanning, run.Status)

	runDir := filepath.Join(s.StateDir(), "runs", run.ID)
	_, err = os.Stat(runDir)
	assert.NoError(t, err, "run directory should exist")
}

func TestFileStore_AppendRollbackEntry_WritesToDisk(t *testing.T) {
	s := newTempStore(t)
	run, err := s.InitRun(context.Background(), "server", false)
	require.NoError(t, err)

	entry := model.RollbackEntry{
		Index:       0,
		CreatedAt:   time.Now(),
		Description: "Restore /etc/ssh/sshd_config before SSH-7408",
		ModuleID:    "ssh-hardening",
		FindingID:   "SSH-7408",
		Kind:        model.RollbackFile,
		Path:        "/etc/ssh/sshd_config",
		BackupPath:  "/var/lib/hardener/backups/test/sshd_config",
	}
	err = s.AppendRollbackEntry(context.Background(), run.ID, entry)
	require.NoError(t, err)

	manifest, err := s.LoadRollbackManifest(context.Background(), run.ID)
	require.NoError(t, err)
	require.Len(t, manifest.Entries, 1)
	assert.Equal(t, "SSH-7408", manifest.Entries[0].FindingID)
}

func TestFileStore_RecordApplied_WritesToDisk(t *testing.T) {
	s := newTempStore(t)
	run, err := s.InitRun(context.Background(), "server", false)
	require.NoError(t, err)

	action := &model.AppliedAction{
		PlannedAction: model.PlannedAction{FindingID: "SSH-7408", ModuleID: "ssh-hardening"},
		Status:        model.ActionApplied,
		AppliedAt:     time.Now(),
	}
	err = s.RecordApplied(context.Background(), run.ID, action)
	require.NoError(t, err)

	runDir := filepath.Join(s.StateDir(), "runs", run.ID)
	data, err := os.ReadFile(filepath.Join(runDir, "applied.json"))
	require.NoError(t, err)

	var actions []*model.AppliedAction
	require.NoError(t, json.Unmarshal(data, &actions))
	require.Len(t, actions, 1)
	assert.Equal(t, "SSH-7408", actions[0].FindingID)
}

func TestFileStore_CompleteRun_UpdatesStatus(t *testing.T) {
	s := newTempStore(t)
	run, err := s.InitRun(context.Background(), "server", false)
	require.NoError(t, err)

	err = s.CompleteRun(context.Background(), run.ID, model.RunCompleted)
	require.NoError(t, err)

	loaded, err := s.GetRun(context.Background(), run.ID)
	require.NoError(t, err)
	assert.Equal(t, model.RunCompleted, loaded.Status)
	assert.NotNil(t, loaded.FinishedAt)
}

func TestFileStore_ListRuns_ReturnsAll(t *testing.T) {
	s := newTempStore(t)
	_, err := s.InitRun(context.Background(), "server", false)
	require.NoError(t, err)
	_, err = s.InitRun(context.Background(), "server", true)
	require.NoError(t, err)

	runs, err := s.ListRuns(context.Background())
	require.NoError(t, err)
	assert.Len(t, runs, 2)
}
