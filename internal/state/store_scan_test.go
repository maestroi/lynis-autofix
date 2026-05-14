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

func TestSaveScanAndLatestScan(t *testing.T) {
	dir := t.TempDir()
	store, err := state.NewFileStore(dir)
	require.NoError(t, err)

	ctx := context.Background()
	result := &model.ScanResult{
		Timestamp:  time.Now().UTC(),
		ReportPath: "/var/log/lynis-report.dat",
		Score:      42,
		Findings: []*model.Finding{
			{ID: "SSH-7408", Category: "SSH", Severity: model.SeverityWarning, Description: "test finding"},
		},
	}

	err = store.SaveScan(ctx, result)
	require.NoError(t, err)

	latest, err := store.LatestScan(ctx)
	require.NoError(t, err)
	assert.Equal(t, result.Score, latest.Score)
	assert.Equal(t, result.ReportPath, latest.ReportPath)
	assert.Len(t, latest.Findings, 1)
	assert.Equal(t, "SSH-7408", latest.Findings[0].ID)
}

func TestLatestScan_NoScans(t *testing.T) {
	dir := t.TempDir()
	store, err := state.NewFileStore(dir)
	require.NoError(t, err)

	_, err = store.LatestScan(context.Background())
	assert.ErrorIs(t, err, state.ErrNoScans)
}

func TestListScans(t *testing.T) {
	dir := t.TempDir()
	store, err := state.NewFileStore(dir)
	require.NoError(t, err)

	ctx := context.Background()
	for i := 0; i < 3; i++ {
		err = store.SaveScan(ctx, &model.ScanResult{
			Timestamp: time.Now().UTC(),
			Score:     i * 10,
		})
		require.NoError(t, err)
	}

	scans, err := store.ListScans(ctx)
	require.NoError(t, err)
	assert.Len(t, scans, 3)
}
