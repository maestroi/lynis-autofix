package debsums

import (
	"context"
	"fmt"
	"time"

	"github.com/maestroi/hardener/internal/executor"
	"github.com/maestroi/hardener/internal/model"
	"github.com/maestroi/hardener/internal/modules"
)

const packageName = "debsums"

// Module remediates PKGS-7394 by installing the debsums package.
type Module struct{}

func New() *Module { return &Module{} }

func (m *Module) Metadata() modules.ModuleMetadata {
	return modules.ModuleMetadata{
		ID:               "pkgs-debsums",
		Name:             "Install debsums",
		Description:      "Installs debsums to enable periodic integrity verification of installed packages",
		Category:         "Software",
		DefaultRisk:      model.RiskLow,
		SupportedDistros: []string{"ubuntu"},
		Tags:             []string{"network-safe", "docker-safe"},
		CanRollback:      true,
		RequiresReboot:   false,
	}
}

func (m *Module) SupportedFindings() []string {
	return []string{"PKGS-7394", "TOOL-5002"}
}

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
		Title:       "Install debsums",
		Description: "Install debsums for dpkg package integrity verification",
		Steps:       []string{fmt.Sprintf("apt-get install -y %s", packageName)},
		Metadata:    map[string]string{"package": packageName},
		Risk:        model.RiskLow,
		CanRollback: true,
		Applicable:  true,
		Tags:        []string{"network-safe", "docker-safe"},
	}, nil
}

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

func (m *Module) Validate(ctx context.Context, _ *model.PlannedAction, inspect executor.Inspector) error {
	ok, err := inspect.IsPackageInstalled(ctx, packageName)
	if err != nil {
		return fmt.Errorf("checking %s after apply: %w", packageName, err)
	}
	if !ok {
		return fmt.Errorf("package %s not found after install", packageName)
	}
	return nil
}

func (m *Module) Rollback(_ context.Context, entry *model.RollbackEntry, _ executor.Executor) error {
	if entry.Kind != model.RollbackPackage {
		return fmt.Errorf("pkgs-debsums rollback: unexpected kind %q", entry.Kind)
	}
	// MVP: skip removal to avoid removing a package with shared dependants.
	// WasInstalled=false means we installed it; WasInstalled=true means it was pre-existing.
	return nil
}
