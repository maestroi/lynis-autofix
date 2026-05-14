package state

import (
	"context"

	"github.com/maestroi/hardener/internal/model"
)

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
	StateDir() string
}
