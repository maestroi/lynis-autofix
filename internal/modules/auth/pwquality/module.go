package pwquality

import (
	"context"
	"fmt"
	"time"

	"github.com/maestroi/hardener/internal/executor"
	"github.com/maestroi/hardener/internal/model"
	"github.com/maestroi/hardener/internal/modules"
)

const packageName = "libpam-pwquality"

// Module remediates AUTH-9262 by ensuring libpam-pwquality is installed.
type Module struct{}

func New() *Module { return &Module{} }

func (m *Module) Metadata() modules.ModuleMetadata {
	return modules.ModuleMetadata{
		ID:               "auth-pam-pwquality",
		Name:             "Install PAM Password Quality",
		Description:      "Installs libpam-pwquality to enforce password complexity rules",
		Category:         "Authentication",
		DefaultRisk:      model.RiskLow,
		SupportedDistros: []string{"ubuntu"},
		Tags:             []string{"network-safe", "docker-safe"},
		CanRollback:      true,
		RequiresReboot:   false,
	}
}

func (m *Module) SupportedFindings() []string {
	return []string{"AUTH-9262"}
}

// Plan checks whether libpam-pwquality is already installed.
// Returns Applicable=false if already present.
func (m *Module) Plan(ctx context.Context, finding *model.Finding, _ *model.Profile, inspect executor.Inspector) (*model.PlannedAction, error) {
	meta := m.Metadata()

	installed, err := inspect.IsPackageInstalled(ctx, packageName)
	if err != nil {
		return nil, fmt.Errorf("checking %s: %w", packageName, err)
	}
	if installed {
		return &model.PlannedAction{
			FindingID:  finding.ID,
			ModuleID:   meta.ID,
			Applicable: false,
			SkipReason: fmt.Sprintf("package %s is already installed", packageName),
		}, nil
	}

	return &model.PlannedAction{
		FindingID:   finding.ID,
		ModuleID:    meta.ID,
		Title:       "Install PAM password quality module",
		Description: fmt.Sprintf("Install %s to enforce password complexity requirements", packageName),
		Steps:       []string{fmt.Sprintf("apt-get install -y %s", packageName)},
		Metadata:    map[string]string{"package": packageName},
		Risk:        model.RiskLow,
		CanRollback: true,
		Applicable:  true,
		Tags:        []string{"network-safe", "docker-safe"},
	}, nil
}

// Apply installs libpam-pwquality.
func (m *Module) Apply(ctx context.Context, action *model.PlannedAction, exec executor.Executor) (*model.AppliedAction, error) {
	if err := exec.InstallPackage(ctx, packageName); err != nil {
		return nil, fmt.Errorf("installing %s: %w", packageName, err)
	}
	return &model.AppliedAction{
		PlannedAction: *action,
		AppliedAt:     time.Now(),
		Status:        model.ActionApplied,
	}, nil
}

// Validate confirms libpam-pwquality is installed.
func (m *Module) Validate(ctx context.Context, _ *model.PlannedAction, inspect executor.Inspector) error {
	ok, err := inspect.IsPackageInstalled(ctx, packageName)
	if err != nil {
		return fmt.Errorf("checking %s: %w", packageName, err)
	}
	if !ok {
		return fmt.Errorf("package %s not found after apply", packageName)
	}
	return nil
}

// Rollback is a no-op (MVP conservatism — we never uninstall packages on rollback).
func (m *Module) Rollback(_ context.Context, entry *model.RollbackEntry, _ executor.Executor) error {
	switch entry.Kind {
	case model.RollbackPackage:
		return nil
	default:
		return fmt.Errorf("auth-pam-pwquality rollback: unexpected kind %q", entry.Kind)
	}
}
