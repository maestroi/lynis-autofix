package cmd

import (
	"bytes"
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

func persistRun(t *testing.T, stateDir string, run *model.Run) {
	t.Helper()
	path := filepath.Join(stateDir, "runs", run.ID, "run.json")
	data, err := json.MarshalIndent(run, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, data, 0640))
}

func setupRunWithPlan(t *testing.T, stateDir string) string {
	t.Helper()
	store, err := state.NewFileStore(stateDir)
	require.NoError(t, err)

	ctx := context.Background()
	run, err := store.InitRun(ctx, "test-profile", false)
	require.NoError(t, err)

	run.ScoreBefore = 40
	run.ScoreAfter = 55
	persistRun(t, stateDir, run)

	actions := []*model.PlannedAction{
		{FindingID: "SSH-7408", ModuleID: "ssh-ciphers", Applicable: true, Risk: model.RiskLow},
		{FindingID: "AUTH-9262", ModuleID: "pam-pwquality", Applicable: false, SkipReason: "already compliant"},
	}
	require.NoError(t, store.SavePlan(ctx, run.ID, actions))

	applied := &model.AppliedAction{
		PlannedAction: *actions[0],
		AppliedAt:     time.Now().UTC(),
		Status:        model.ActionApplied,
	}
	require.NoError(t, store.RecordApplied(ctx, run.ID, applied))
	require.NoError(t, store.CompleteRun(ctx, run.ID, model.RunCompleted))

	return run.ID
}

func TestReportCmd_History(t *testing.T) {
	dir := t.TempDir()
	setupRunWithPlan(t, dir)

	buf := &bytes.Buffer{}
	root := newTestRoot(buf)
	root.SetArgs([]string{"report", "--state-dir", dir})
	err := root.Execute()
	require.NoError(t, err)
	out := buf.String()
	assert.Contains(t, out, "test-profile")
	assert.Contains(t, out, "55")
}

func TestReportCmd_History_NoRuns(t *testing.T) {
	dir := t.TempDir()

	buf := &bytes.Buffer{}
	root := newTestRoot(buf)
	root.SetArgs([]string{"report", "--state-dir", dir})
	err := root.Execute()
	require.NoError(t, err)
	assert.Contains(t, buf.String(), "No runs found.")
}

func TestReportCmd_DrillDown_NoLynis(t *testing.T) {
	dir := t.TempDir()
	runID := setupRunWithPlan(t, dir)

	buf := &bytes.Buffer{}
	root := newTestRoot(buf)
	root.SetArgs([]string{"report", "--state-dir", dir, "--run-id", runID, "--lynis-binary", "/nonexistent/lynis"})
	err := root.Execute()
	require.NoError(t, err)
	out := buf.String()
	assert.Contains(t, out, "live comparison unavailable")
	assert.Contains(t, out, runID)
}

func TestReportCmd_DrillDown_JSONOutput(t *testing.T) {
	dir := t.TempDir()
	runID := setupRunWithPlan(t, dir)

	buf := &bytes.Buffer{}
	root := newTestRoot(buf)
	root.SetArgs([]string{"report", "--state-dir", dir, "--run-id", runID,
		"--lynis-binary", "/nonexistent/lynis", "--output", "json"})
	err := root.Execute()
	require.NoError(t, err)

	var cr struct {
		RunID string `json:"run_id"`
	}
	require.NoError(t, json.Unmarshal(buf.Bytes(), &cr))
	assert.Equal(t, runID, cr.RunID)
}

func TestReportCmd_DrillDown_RunNotFound(t *testing.T) {
	dir := t.TempDir()

	buf := &bytes.Buffer{}
	root := newTestRoot(buf)
	root.SetArgs([]string{"report", "--state-dir", dir, "--run-id", "nonexistent"})
	err := root.Execute()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "nonexistent")
}
