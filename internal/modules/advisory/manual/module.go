package manual

import (
	"context"
	"fmt"
	"time"

	"github.com/maestroi/hardener/internal/executor"
	"github.com/maestroi/hardener/internal/model"
	"github.com/maestroi/hardener/internal/modules"
)

// supportedFindings lists Lynis IDs handled only by this advisory module. Empty once all
// skipped-findings modules are registered — unregistered findings surface as "no module".
var supportedFindings = []string{}

// Module marks manual-only findings as explicitly unsupported by automation.
type Module struct{}

func New() *Module { return &Module{} }

func (m *Module) Metadata() modules.ModuleMetadata {
	return modules.ModuleMetadata{
		ID:               "advisory-manual",
		Name:             "Manual Advisory Checks",
		Description:      "Catch-all for findings with no registered module",
		Category:         "Advisory",
		DefaultRisk:      model.RiskNone,
		SupportedDistros: []string{"ubuntu"},
		Tags:             []string{"manual"},
		CanRollback:      false,
		RequiresReboot:   false,
	}
}

func (m *Module) SupportedFindings() []string {
	return supportedFindings
}

func (m *Module) Plan(_ context.Context, finding *model.Finding, _ *model.Profile, _ executor.Inspector) (*model.PlannedAction, error) {
	return &model.PlannedAction{
		FindingID:  finding.ID,
		ModuleID:   m.Metadata().ID,
		Applicable: false,
		SkipReason: fmt.Sprintf("manual review required for %s; automated remediation is not implemented", finding.ID),
		Risk:       model.RiskNone,
	}, nil
}

func (m *Module) Apply(_ context.Context, action *model.PlannedAction, _ executor.Executor) (*model.AppliedAction, error) {
	return &model.AppliedAction{
		PlannedAction: *action,
		AppliedAt:     time.Now(),
		Status:        model.ActionSkipped,
	}, nil
}

func (m *Module) Validate(_ context.Context, _ *model.PlannedAction, _ executor.Inspector) error {
	return nil
}

func (m *Module) Rollback(_ context.Context, _ *model.RollbackEntry, _ executor.Executor) error {
	return nil
}
