package modules

import (
	"context"

	"github.com/maestroi/hardener/internal/executor"
	"github.com/maestroi/hardener/internal/model"
)

// ModuleMetadata describes a remediation module's identity and capabilities.
type ModuleMetadata struct {
	ID               string
	Name             string
	Description      string
	Category         string
	DefaultRisk      model.RiskLevel
	SupportedDistros []string // ["ubuntu-22.04", "ubuntu-24.04"] or ["ubuntu"]
	Tags             []string // "network-safe", "docker-safe", "validator-safe"
	CanRollback      bool
	RequiresReboot   bool
}

// Module is the interface every remediation module must implement.
// Modules are stateless — no shared state between method calls.
type Module interface {
	Metadata() ModuleMetadata
	SupportedFindings() []string

	// Plan inspects current state (read-only via Inspector) and returns what Apply would do.
	// Returns Applicable=false with SkipReason if the system already meets requirements.
	Plan(ctx context.Context, finding *model.Finding, profile *model.Profile, inspect executor.Inspector) (*model.PlannedAction, error)

	// Apply executes the remediation. Receives the PlannedAction from Plan(); module holds no state.
	Apply(ctx context.Context, action *model.PlannedAction, exec executor.Executor) (*model.AppliedAction, error)

	// Validate confirms the desired end state is present after Apply (read-only).
	Validate(ctx context.Context, action *model.PlannedAction, inspect executor.Inspector) error

	// Rollback reverses the changes described by a single RollbackEntry.
	// Called by the rollback engine, not by the module itself.
	Rollback(ctx context.Context, entry *model.RollbackEntry, exec executor.Executor) error
}
