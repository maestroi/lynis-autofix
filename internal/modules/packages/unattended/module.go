package unattended

import (
	"context"
	"fmt"
	"time"

	"github.com/maestroi/hardener/internal/executor"
	"github.com/maestroi/hardener/internal/model"
	"github.com/maestroi/hardener/internal/modules"
)

const (
	packageName = "unattended-upgrades"
	serviceName = "unattended-upgrades"
)

// Module remediates PKGS-7370 by installing and enabling unattended-upgrades.
type Module struct{}

func New() *Module { return &Module{} }

func (m *Module) Metadata() modules.ModuleMetadata {
	return modules.ModuleMetadata{
		ID:               "pkgs-unattended-upgrades",
		Name:             "Enable Unattended Upgrades",
		Description:      "Installs and enables unattended-upgrades to apply security patches automatically",
		Category:         "Software",
		DefaultRisk:      model.RiskLow,
		SupportedDistros: []string{"ubuntu"},
		Tags:             []string{"network-safe", "docker-safe"},
		CanRollback:      true,
		RequiresReboot:   false,
	}
}

func (m *Module) SupportedFindings() []string {
	return []string{"PKGS-7370"}
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
			SkipReason: fmt.Sprintf("already compliant: package %s is installed and service is active/enabled", packageName),
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
		Title:       "Enable unattended-upgrades",
		Description: "Install and enable automatic security patching via unattended-upgrades",
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
		return fmt.Errorf("service %s is not active after apply", serviceName)
	}
	return nil
}

func (m *Module) Rollback(_ context.Context, entry *model.RollbackEntry, _ executor.Executor) error {
	switch entry.Kind {
	case model.RollbackPackage:
		// MVP: skip removal to avoid dependency surprises.
		return nil
	case model.RollbackService:
		// Service rollback handled by the generic rollback manager.
		return nil
	default:
		return fmt.Errorf("pkgs-unattended-upgrades rollback: unexpected kind %q", entry.Kind)
	}
}
