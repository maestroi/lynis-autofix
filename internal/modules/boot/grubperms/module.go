package grubperms

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/maestroi/hardener/internal/executor"
	"github.com/maestroi/hardener/internal/model"
	"github.com/maestroi/hardener/internal/modules"
)

const GrubCfgPath = "/boot/grub/grub.cfg"

type Module struct{}

func New() *Module { return &Module{} }

func (m *Module) Metadata() modules.ModuleMetadata {
	return modules.ModuleMetadata{
		ID:               "boot-grub-perms",
		Name:             "Secure GRUB Configuration Permissions",
		Description:      "Sets /boot/grub/grub.cfg to mode 600 so only root can read the bootloader config",
		Category:         "Boot",
		DefaultRisk:      model.RiskLow,
		SupportedDistros: []string{"ubuntu"},
		Tags:             []string{"network-safe", "docker-safe"},
		CanRollback:      true,
		RequiresReboot:   false,
	}
}

func (m *Module) SupportedFindings() []string {
	return []string{"BOOT-5264"}
}

func (m *Module) Plan(ctx context.Context, finding *model.Finding, _ *model.Profile, inspect executor.Inspector) (*model.PlannedAction, error) {
	meta := m.Metadata()

	exists, err := inspect.FileExists(ctx, GrubCfgPath)
	if err != nil {
		return nil, fmt.Errorf("boot-grub-perms: checking %s: %w", GrubCfgPath, err)
	}
	if !exists {
		return &model.PlannedAction{
			FindingID:  finding.ID,
			ModuleID:   meta.ID,
			Applicable: false,
			SkipReason: fmt.Sprintf("manual prerequisite required: %s does not exist; GRUB may not be installed", GrubCfgPath),
		}, nil
	}

	out, err := inspect.RunReadOnly(ctx, "stat", "-c", "%a", GrubCfgPath)
	if err != nil {
		return nil, fmt.Errorf("boot-grub-perms: stat %s: %w", GrubCfgPath, err)
	}
	mode := strings.TrimSpace(out.Stdout)
	if mode == "600" || mode == "400" {
		return &model.PlannedAction{
			FindingID:  finding.ID,
			ModuleID:   meta.ID,
			Applicable: false,
			SkipReason: fmt.Sprintf("already compliant: %s already has mode %s", GrubCfgPath, mode),
		}, nil
	}

	return &model.PlannedAction{
		FindingID:   finding.ID,
		ModuleID:    meta.ID,
		Title:       "Set GRUB config permissions to 600",
		Description: fmt.Sprintf("chmod 600 %s (currently %s)", GrubCfgPath, mode),
		Steps:       []string{fmt.Sprintf("chmod 600 %s", GrubCfgPath)},
		Metadata:    map[string]string{"path": GrubCfgPath, "orig_mode": mode},
		Risk:        model.RiskLow,
		CanRollback: true,
		Applicable:  true,
		Tags:        []string{"network-safe", "docker-safe"},
	}, nil
}

func (m *Module) Apply(ctx context.Context, action *model.PlannedAction, exec executor.Executor) (*model.AppliedAction, error) {
	if err := exec.SetFileMode(ctx, GrubCfgPath, 0600); err != nil {
		return nil, fmt.Errorf("boot-grub-perms: chmod %s: %w", GrubCfgPath, err)
	}
	return &model.AppliedAction{
		PlannedAction: *action,
		AppliedAt:     time.Now(),
		Status:        model.ActionApplied,
	}, nil
}

func (m *Module) Validate(ctx context.Context, _ *model.PlannedAction, inspect executor.Inspector) error {
	out, err := inspect.RunReadOnly(ctx, "stat", "-c", "%a", GrubCfgPath)
	if err != nil {
		return fmt.Errorf("boot-grub-perms: stat %s: %w", GrubCfgPath, err)
	}
	mode := strings.TrimSpace(out.Stdout)
	if mode != "600" && mode != "400" {
		return fmt.Errorf("boot-grub-perms: %s has mode %s, want 600", GrubCfgPath, mode)
	}
	return nil
}

func (m *Module) Rollback(ctx context.Context, entry *model.RollbackEntry, exec executor.Executor) error {
	switch entry.Kind {
	case model.RollbackFile:
		if err := exec.SetFileMode(ctx, entry.Path, entry.OrigMode); err != nil {
			return fmt.Errorf("boot-grub-perms: restoring mode on %s: %w", entry.Path, err)
		}
		return nil
	default:
		return fmt.Errorf("boot-grub-perms rollback: unexpected kind %q", entry.Kind)
	}
}
