package aide

import (
	"context"
	"fmt"
	"time"

	"github.com/maestroi/hardener/internal/executor"
	"github.com/maestroi/hardener/internal/model"
	"github.com/maestroi/hardener/internal/modules"
)

const (
	packageName = "aide"
	DBPath      = "/var/lib/aide/aide.db.new"
)

type Module struct{}

func New() *Module { return &Module{} }

func (m *Module) Metadata() modules.ModuleMetadata {
	return modules.ModuleMetadata{
		ID:               "pkgs-aide",
		Name:             "Install AIDE File Integrity Tool",
		Description:      "Installs aide and initialises its database for file integrity monitoring",
		Category:         "Packages",
		DefaultRisk:      model.RiskLow,
		SupportedDistros: []string{"ubuntu"},
		Tags:             []string{"network-safe", "docker-safe"},
		CanRollback:      true,
		RequiresReboot:   false,
	}
}

func (m *Module) SupportedFindings() []string {
	return []string{"FINT-4350"}
}

func (m *Module) Plan(ctx context.Context, finding *model.Finding, _ *model.Profile, inspect executor.Inspector) (*model.PlannedAction, error) {
	meta := m.Metadata()

	installed, err := inspect.IsPackageInstalled(ctx, packageName)
	if err != nil {
		return nil, fmt.Errorf("pkgs-aide: checking %s: %w", packageName, err)
	}

	dbExists, err := inspect.FileExists(ctx, DBPath)
	if err != nil {
		return nil, fmt.Errorf("pkgs-aide: checking %s: %w", DBPath, err)
	}

	if installed && dbExists {
		return &model.PlannedAction{
			FindingID:  finding.ID,
			ModuleID:   meta.ID,
			Applicable: false,
			SkipReason: fmt.Sprintf("package %s is installed and database %s exists", packageName, DBPath),
		}, nil
	}

	var steps []string
	if !installed {
		steps = append(steps, fmt.Sprintf("apt-get install -y %s", packageName))
	}
	if !dbExists {
		steps = append(steps, "aideinit --yes")
	}

	return &model.PlannedAction{
		FindingID:   finding.ID,
		ModuleID:    meta.ID,
		Title:       "Install AIDE and initialise database",
		Description: "Install file integrity monitoring tool and create its baseline database",
		Steps:       steps,
		Metadata:    map[string]string{"package": packageName, "db_path": DBPath},
		Risk:        model.RiskLow,
		CanRollback: true,
		Applicable:  true,
		Tags:        []string{"network-safe", "docker-safe"},
	}, nil
}

func (m *Module) Apply(ctx context.Context, action *model.PlannedAction, exec executor.Executor) (*model.AppliedAction, error) {
	installed, _ := exec.IsPackageInstalled(ctx, packageName)
	if !installed {
		if err := exec.InstallPackage(ctx, packageName); err != nil {
			return nil, fmt.Errorf("pkgs-aide: installing %s: %w", packageName, err)
		}
	}

	dbExists, _ := exec.FileExists(ctx, DBPath)
	if !dbExists {
		if _, err := exec.Run(ctx, "aideinit", "--yes"); err != nil {
			return nil, fmt.Errorf("pkgs-aide: aideinit: %w", err)
		}
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
		return fmt.Errorf("pkgs-aide: checking package: %w", err)
	}
	if !ok {
		return fmt.Errorf("pkgs-aide: package %s not installed after apply", packageName)
	}

	exists, err := inspect.FileExists(ctx, DBPath)
	if err != nil {
		return fmt.Errorf("pkgs-aide: checking DB: %w", err)
	}
	if !exists {
		return fmt.Errorf("pkgs-aide: database %s not found after apply", DBPath)
	}
	return nil
}

func (m *Module) Rollback(_ context.Context, entry *model.RollbackEntry, _ executor.Executor) error {
	switch entry.Kind {
	case model.RollbackPackage:
		return nil
	default:
		return fmt.Errorf("pkgs-aide rollback: unexpected kind %q", entry.Kind)
	}
}
