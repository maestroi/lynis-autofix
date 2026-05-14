package state_test

import (
	"context"
	"testing"
	"time"

	"github.com/maestroi/hardener/internal/model"
	"github.com/maestroi/hardener/internal/state"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadPlan_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	store, err := state.NewFileStore(dir)
	require.NoError(t, err)

	ctx := context.Background()
	run, err := store.InitRun(ctx, "test-profile", false)
	require.NoError(t, err)

	actions := []*model.PlannedAction{
		{FindingID: "SSH-7408", ModuleID: "ssh-ciphers", Applicable: true, Risk: model.RiskLow},
		{FindingID: "AUTH-9262", ModuleID: "pam-pwquality", Applicable: false, SkipReason: "already compliant"},
	}
	require.NoError(t, store.SavePlan(ctx, run.ID, actions))

	loaded, err := store.LoadPlan(ctx, run.ID)
	require.NoError(t, err)
	require.Len(t, loaded, 2)
	assert.Equal(t, "SSH-7408", loaded[0].FindingID)
	assert.True(t, loaded[0].Applicable)
	assert.Equal(t, "AUTH-9262", loaded[1].FindingID)
	assert.False(t, loaded[1].Applicable)
}

func TestLoadApplied_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	store, err := state.NewFileStore(dir)
	require.NoError(t, err)

	ctx := context.Background()
	run, err := store.InitRun(ctx, "test-profile", false)
	require.NoError(t, err)

	action := &model.AppliedAction{
		PlannedAction: model.PlannedAction{FindingID: "SSH-7408", ModuleID: "ssh-ciphers"},
		AppliedAt:     time.Now().UTC(),
		Status:        model.ActionApplied,
	}
	require.NoError(t, store.RecordApplied(ctx, run.ID, action))

	loaded, err := store.LoadApplied(ctx, run.ID)
	require.NoError(t, err)
	require.Len(t, loaded, 1)
	assert.Equal(t, "SSH-7408", loaded[0].FindingID)
	assert.Equal(t, model.ActionApplied, loaded[0].Status)
}

func TestLoadPlan_RunNotFound(t *testing.T) {
	dir := t.TempDir()
	store, err := state.NewFileStore(dir)
	require.NoError(t, err)

	_, err = store.LoadPlan(context.Background(), "nonexistent-run")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "nonexistent-run")
}
