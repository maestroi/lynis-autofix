package planner

import (
	"context"
	"fmt"

	"github.com/maestroi/hardener/internal/executor"
	"github.com/maestroi/hardener/internal/model"
	"github.com/maestroi/hardener/internal/registry"
)

// Planner maps a slice of Findings to PlannedActions using the module registry.
type Planner struct {
	reg     *registry.Registry
	inspect executor.Inspector
}

// New creates a Planner. inspect is used by Module.Plan() for read-only system state access.
func New(reg *registry.Registry, inspect executor.Inspector) *Planner {
	return &Planner{reg: reg, inspect: inspect}
}

// Plan calls Module.Plan() for each finding. Findings with no registered module
// are returned as skipped actions rather than errors.
func (p *Planner) Plan(ctx context.Context, findings []*model.Finding, profile *model.Profile) ([]*model.PlannedAction, error) {
	actions := make([]*model.PlannedAction, 0, len(findings))
	seenFindingID := make(map[string]struct{}, len(findings))

	for _, f := range findings {
		if _, seen := seenFindingID[f.ID]; seen {
			continue
		}
		seenFindingID[f.ID] = struct{}{}

		mod, ok := p.reg.Lookup(f.ID)
		if !ok {
			actions = append(actions, &model.PlannedAction{
				FindingID:  f.ID,
				Applicable: false,
				SkipReason: fmt.Sprintf("no module registered for finding %s", f.ID),
			})
			continue
		}

		action, err := mod.Plan(ctx, f, profile, p.inspect)
		if err != nil {
			return nil, fmt.Errorf("planning %s via %s: %w", f.ID, mod.Metadata().ID, err)
		}
		actions = append(actions, action)
	}

	return actions, nil
}
