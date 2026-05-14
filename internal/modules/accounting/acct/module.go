package acct

import (
	"context"
	"fmt"
	"time"

	"github.com/maestroi/hardener/internal/executor"
	"github.com/maestroi/hardener/internal/model"
	"github.com/maestroi/hardener/internal/modules"
)

const (
	packageName = "acct"
	serviceName = "acct"
)

// Module remediates ACCT-9622 by installing process accounting (acct).
type Module struct{}

func New() *Module { return &Module{} }

func (m *Module) Metadata() modules.ModuleMetadata {
	return modules.ModuleMetadata{
		ID:               "accounting-acct",
		Name:             "Enable Process Accounting",
		Description:      "Installs and enables the acct daemon for per-user process and login accounting",
		Category:         "Accounting",
		DefaultRisk:      model.RiskLow,
		SupportedDistros: []string{"ubuntu"},
		Tags:             []string{"network-safe", "docker-safe"},
		CanRollback:      true,
		RequiresReboot:   false,
	}
}

func (m *Module) SupportedFindings() []string {
	return []string{"ACCT-9622"}
}

func (m *Module) Plan(ctx context.Context, finding *model.Finding, _ *model.Profile, inspect executor.Inspector) (*model.PlannedAction, error) {
	meta := m.Metadata()

	installed, err := inspect.IsPackageInstalled(ctx, packageName)
	if err != nil {
		return nil, fmt.Errorf("checking %s: %w", packageName, err)
	}

	svcState, err := inspect.ServiceState(ctx, serviceName)
	if err != nil {
		return nil, fmt.Errorf("checking service %s: %w", serviceName, err)
	}

	if installed && svcState.Active && svcState.Enabled {
		return &model.PlannedAction{
			FindingID:  finding.ID,
			ModuleID:   meta.ID,
			Applicable: false,
			SkipReason: fmt.Sprintf("package %s is installed and service is active/enabled", packageName),
		}, nil
	}

	metadata := map[string]string{"package": packageName, "service": serviceName}
	if installed {
		metadata["skip_install"] = "true"
	}

	var steps []string
	if !installed {
		steps = append(steps, fmt.Sprintf("apt-get install -y %s", packageName))
	}
	steps = append(steps, fmt.Sprintf("systemctl enable %s", serviceName))
	steps = append(steps, fmt.Sprintf("systemctl start %s", serviceName))

	return &model.PlannedAction{
		FindingID:   finding.ID,
		ModuleID:    meta.ID,
		Title:       "Enable process accounting",
		Description: "Install acct and enable the process accounting daemon",
		Steps:       steps,
		Metadata:    metadata,
		Risk:        model.RiskLow,
		CanRollback: true,
		Applicable:  true,
		Tags:        []string{"network-safe", "docker-safe"},
	}, nil
}

func (m *Module) Apply(ctx context.Context, action *model.PlannedAction, exec executor.Executor) (*model.AppliedAction, error) {
	if action.Metadata["skip_install"] != "true" {
		if err := exec.InstallPackage(ctx, packageName); err != nil {
			return nil, fmt.Errorf("installing %s: %w", packageName, err)
		}
	}
	if err := exec.EnableService(ctx, serviceName); err != nil {
		return nil, fmt.Errorf("enabling %s: %w", serviceName, err)
	}
	if err := exec.StartService(ctx, serviceName); err != nil {
		return nil, fmt.Errorf("starting %s: %w", serviceName, err)
	}
	return &model.AppliedAction{
		PlannedAction: *action,
		AppliedAt:     time.Now(),
		Status:        model.ActionApplied,
	}, nil
}

func (m *Module) Validate(ctx context.Context, _ *model.PlannedAction, inspect executor.Inspector) error {
	ok, err := inspect.IsPackageInstalled(ctx, packageName)
	if err != nil {
		return fmt.Errorf("checking %s: %w", packageName, err)
	}
	if !ok {
		return fmt.Errorf("package %s not found after apply", packageName)
	}

	state, err := inspect.ServiceState(ctx, serviceName)
	if err != nil {
		return fmt.Errorf("checking service %s: %w", serviceName, err)
	}
	if !state.Active {
		return fmt.Errorf("service %s not active after apply", serviceName)
	}
	return nil
}

func (m *Module) Rollback(_ context.Context, entry *model.RollbackEntry, _ executor.Executor) error {
	switch entry.Kind {
	case model.RollbackPackage, model.RollbackService:
		return nil
	default:
		return fmt.Errorf("accounting-acct rollback: unexpected kind %q", entry.Kind)
	}
}
