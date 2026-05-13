package reporter

import (
	"context"

	"github.com/maestroi/hardener/internal/model"
)

// Reporter renders output to the operator. Implementations must not contain business logic.
type Reporter interface {
	Audit(ctx context.Context, findings []*model.Finding, score int) error
	Plan(ctx context.Context, actions []*model.PlannedAction) error
	Applied(ctx context.Context, run *model.Run, actions []*model.AppliedAction) error
	Score(ctx context.Context, before, after int, skipped []string) error
	RollbackPreview(ctx context.Context, manifest *model.RollbackManifest) error
	History(ctx context.Context, runs []*model.Run) error
}
