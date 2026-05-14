package firewall

import (
	"context"
	"fmt"
	"time"

	"github.com/maestroi/hardener/internal/executor"
	"github.com/maestroi/hardener/internal/model"
	"github.com/maestroi/hardener/internal/modules"
)

const (
	packageName = "ufw"
	serviceName = "ufw"
)

type Module struct{}

func New() *Module { return &Module{} }

func (m *Module) Metadata() modules.ModuleMetadata {
	return modules.ModuleMetadata{
		ID:               "network-firewall",
		Name:             "Enable UFW Firewall",
		Description:      "Installs and enables UFW with default-deny incoming policy",
		Category:         "Network",
		DefaultRisk:      model.RiskMedium,
		SupportedDistros: []string{"ubuntu"},
		Tags:             []string{"network-safe"},
		CanRollback:      true,
		RequiresReboot:   false,
	}
}

func (m *Module) SupportedFindings() []string {
	return []string{"FIRE-4513"}
}

func (m *Module) Plan(ctx context.Context, finding *model.Finding, _ *model.Profile, inspect executor.Inspector) (*model.PlannedAction, error) {
	meta := m.Metadata()

	installed, err := inspect.IsPackageInstalled(ctx, packageName)
	if err != nil {
		return nil, fmt.Errorf("network-firewall: checking %s: %w", packageName, err)
	}

	svc, err := inspect.ServiceState(ctx, serviceName)
	if err != nil {
		return nil, fmt.Errorf("network-firewall: checking service %s: %w", serviceName, err)
	}

	if installed && svc.Active && svc.Enabled {
		return &model.PlannedAction{
			FindingID:  finding.ID,
			ModuleID:   meta.ID,
			Applicable: false,
			SkipReason: "already compliant: ufw is installed and service is active/enabled",
		}, nil
	}

	var steps []string
	if !installed {
		steps = append(steps, "apt-get install -y ufw")
	}
	steps = append(steps,
		"ufw default deny incoming",
		"ufw default allow outgoing",
		"ufw --force enable",
		"systemctl enable ufw",
	)

	return &model.PlannedAction{
		FindingID:   finding.ID,
		ModuleID:    meta.ID,
		Title:       "Enable UFW firewall",
		Description: "Install UFW and set default-deny incoming policy",
		Steps:       steps,
		Metadata:    map[string]string{"package": packageName, "service": serviceName},
		Risk:        model.RiskMedium,
		Impact:      "Enables firewall with default-deny incoming. Existing allow rules are preserved. SSH access may be affected if port 22 is not allowed.",
		CanRollback: true,
		Applicable:  true,
		Tags:        []string{"network-safe"},
	}, nil
}

func (m *Module) Apply(ctx context.Context, action *model.PlannedAction, exec executor.Executor) (*model.AppliedAction, error) {
	installed, _ := exec.IsPackageInstalled(ctx, packageName)
	if !installed {
		if err := exec.InstallPackage(ctx, packageName); err != nil {
			return nil, fmt.Errorf("network-firewall: installing %s: %w", packageName, err)
		}
	}

	if _, err := exec.Run(ctx, "ufw", "default", "deny", "incoming"); err != nil {
		return nil, fmt.Errorf("network-firewall: ufw default deny: %w", err)
	}
	if _, err := exec.Run(ctx, "ufw", "default", "allow", "outgoing"); err != nil {
		return nil, fmt.Errorf("network-firewall: ufw default allow: %w", err)
	}
	if _, err := exec.Run(ctx, "ufw", "--force", "enable"); err != nil {
		return nil, fmt.Errorf("network-firewall: ufw enable: %w", err)
	}
	if err := exec.EnableService(ctx, serviceName); err != nil {
		return nil, fmt.Errorf("network-firewall: enabling %s: %w", serviceName, err)
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
		return fmt.Errorf("network-firewall: checking package: %w", err)
	}
	if !ok {
		return fmt.Errorf("network-firewall: package %s not installed after apply", packageName)
	}

	svc, err := inspect.ServiceState(ctx, serviceName)
	if err != nil {
		return fmt.Errorf("network-firewall: checking service: %w", err)
	}
	if !svc.Enabled {
		return fmt.Errorf("network-firewall: service %s is not enabled after apply", serviceName)
	}
	return nil
}

func (m *Module) Rollback(_ context.Context, entry *model.RollbackEntry, _ executor.Executor) error {
	switch entry.Kind {
	case model.RollbackPackage:
		return nil
	case model.RollbackService:
		return nil
	default:
		return fmt.Errorf("network-firewall rollback: unexpected kind %q", entry.Kind)
	}
}
