package debpurge

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/maestroi/hardener/internal/executor"
	"github.com/maestroi/hardener/internal/model"
	"github.com/maestroi/hardener/internal/modules"
)

type Module struct{}

func New() *Module { return &Module{} }

func (m *Module) Metadata() modules.ModuleMetadata {
	return modules.ModuleMetadata{
		ID:               "pkgs-debpurge",
		Name:             "Purge Removed Packages",
		Description:      "Purges packages in removed-but-not-purged state (dpkg rc) to eliminate leftover config files",
		Category:         "Packages",
		DefaultRisk:      model.RiskLow,
		SupportedDistros: []string{"ubuntu"},
		Tags:             []string{"network-safe", "docker-safe"},
		CanRollback:      false,
		RequiresReboot:   false,
	}
}

func (m *Module) SupportedFindings() []string {
	return []string{"DEB-0810"}
}

func (m *Module) Plan(ctx context.Context, finding *model.Finding, _ *model.Profile, inspect executor.Inspector) (*model.PlannedAction, error) {
	meta := m.Metadata()

	out, err := inspect.RunReadOnly(ctx, "dpkg", "--list")
	if err != nil {
		return nil, fmt.Errorf("pkgs-debpurge: running dpkg --list: %w", err)
	}

	var rcPkgs []string
	for _, line := range strings.Split(out.Stdout, "\n") {
		if strings.HasPrefix(line, "rc ") || strings.HasPrefix(line, "rc\t") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				rcPkgs = append(rcPkgs, fields[1])
			}
		}
	}

	if len(rcPkgs) == 0 {
		return &model.PlannedAction{
			FindingID:  finding.ID,
			ModuleID:   meta.ID,
			Applicable: false,
			SkipReason: "already compliant: no removed-but-not-purged packages found",
		}, nil
	}

	return &model.PlannedAction{
		FindingID:   finding.ID,
		ModuleID:    meta.ID,
		Title:       "Purge removed packages",
		Description: fmt.Sprintf("Purge %d removed packages: %s", len(rcPkgs), strings.Join(rcPkgs, ", ")),
		Steps:       []string{fmt.Sprintf("dpkg --purge %s", strings.Join(rcPkgs, " "))},
		Metadata:    map[string]string{"rc_packages": strings.Join(rcPkgs, ",")},
		Risk:        model.RiskLow,
		CanRollback: false,
		Applicable:  true,
		Tags:        []string{"network-safe", "docker-safe"},
	}, nil
}

func (m *Module) Apply(ctx context.Context, action *model.PlannedAction, exec executor.Executor) (*model.AppliedAction, error) {
	pkgList := action.Metadata["rc_packages"]
	if pkgList == "" {
		return &model.AppliedAction{
			PlannedAction: *action,
			AppliedAt:     time.Now(),
			Status:        model.ActionApplied,
		}, nil
	}

	for _, pkg := range strings.Split(pkgList, ",") {
		pkg = strings.TrimSpace(pkg)
		if pkg == "" {
			continue
		}
		if _, err := exec.Run(ctx, "dpkg", "--purge", pkg); err != nil {
			return nil, fmt.Errorf("pkgs-debpurge: purging %s: %w", pkg, err)
		}
	}

	return &model.AppliedAction{
		PlannedAction: *action,
		AppliedAt:     time.Now(),
		Status:        model.ActionApplied,
	}, nil
}

func (m *Module) Validate(ctx context.Context, _ *model.PlannedAction, inspect executor.Inspector) error {
	out, err := inspect.RunReadOnly(ctx, "dpkg", "--list")
	if err != nil {
		return fmt.Errorf("pkgs-debpurge: running dpkg --list: %w", err)
	}
	for _, line := range strings.Split(out.Stdout, "\n") {
		if strings.HasPrefix(line, "rc ") || strings.HasPrefix(line, "rc\t") {
			return fmt.Errorf("pkgs-debpurge: removed-not-purged packages still present after apply")
		}
	}
	return nil
}

func (m *Module) Rollback(_ context.Context, entry *model.RollbackEntry, _ executor.Executor) error {
	switch entry.Kind {
	case model.RollbackPackage:
		return nil // purged packages cannot be un-purged
	default:
		return fmt.Errorf("pkgs-debpurge rollback: unexpected kind %q", entry.Kind)
	}
}
