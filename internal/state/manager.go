package state

import (
	"context"
	"errors"

	"github.com/maestroi/hardener/internal/model"
)

// ErrNoScans is returned by LatestScan when no scans have been saved.
var ErrNoScans = errors.New("no scans found")

// StateManager owns the lifecycle of run directories and state persistence.
type StateManager interface {
	InitRun(ctx context.Context, profileName string, dryRun bool) (*model.Run, error)
	SavePlan(ctx context.Context, runID string, actions []*model.PlannedAction) error
	RecordApplied(ctx context.Context, runID string, action *model.AppliedAction) error
	AppendRollbackEntry(ctx context.Context, runID string, entry model.RollbackEntry) error
	CompleteRun(ctx context.Context, runID string, status model.RunStatus) error
	GetRun(ctx context.Context, runID string) (*model.Run, error)
	ListRuns(ctx context.Context) ([]*model.Run, error)
	LoadRollbackManifest(ctx context.Context, runID string) (*model.RollbackManifest, error)
	// LoadPlan loads the planned actions for a given run.
	LoadPlan(ctx context.Context, runID string) ([]*model.PlannedAction, error)
	// LoadApplied loads the applied actions for a given run.
	LoadApplied(ctx context.Context, runID string) ([]*model.AppliedAction, error)
	StateDir() string

	// SaveScan persists a scan result to <stateDir>/scans/.
	SaveScan(ctx context.Context, result *model.ScanResult) error
	// LatestScan returns the most recently saved scan result.
	// Returns ErrNoScans if no scans have been saved.
	LatestScan(ctx context.Context) (*model.ScanResult, error)
	// ListScans returns all saved scan results in chronological order.
	ListScans(ctx context.Context) ([]*model.ScanResult, error)
}
