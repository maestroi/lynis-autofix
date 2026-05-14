package modules

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/maestroi/hardener/internal/executor"
	"github.com/maestroi/hardener/internal/model"
	hmod "github.com/maestroi/hardener/internal/modules"
)

const (
	ConfPath    = "/etc/sysctl.d/99-hardener-modules.conf"
	sysctlKey   = "kernel.modules_disabled"
	sysctlVal   = "1"
	confContent = "# Managed by hardener — do not edit manually.\nkernel.modules_disabled = 1\n"
)

type Module struct{}

func New() *Module { return &Module{} }

func (m *Module) Metadata() hmod.ModuleMetadata {
	return hmod.ModuleMetadata{
		ID:               "kernel-modules-disabled",
		Name:             "Disable Kernel Module Loading",
		Description:      "Sets kernel.modules_disabled=1 to prevent loading new kernel modules at runtime",
		Category:         "Kernel",
		DefaultRisk:      model.RiskCritical,
		SupportedDistros: []string{"ubuntu"},
		Tags:             []string{"network-safe"},
		CanRollback:      true,
		RequiresReboot:   true,
	}
}

func (m *Module) SupportedFindings() []string {
	return []string{"KRNL-5830"}
}

func (m *Module) Plan(ctx context.Context, finding *model.Finding, _ *model.Profile, inspect executor.Inspector) (*model.PlannedAction, error) {
	meta := m.Metadata()

	current, err := inspect.GetSysctl(ctx, sysctlKey)
	if err != nil {
		return nil, fmt.Errorf("kernel-modules-disabled: reading %s: %w", sysctlKey, err)
	}

	if strings.TrimSpace(current) == sysctlVal {
		return &model.PlannedAction{
			FindingID:  finding.ID,
			ModuleID:   meta.ID,
			Applicable: false,
			SkipReason: fmt.Sprintf("%s is already %s", sysctlKey, sysctlVal),
		}, nil
	}

	return &model.PlannedAction{
		FindingID:   finding.ID,
		ModuleID:    meta.ID,
		Title:       "Disable kernel module loading",
		Description: fmt.Sprintf("Write %s and apply %s=1 via sysctl", ConfPath, sysctlKey),
		Steps: []string{
			fmt.Sprintf("write %s", ConfPath),
			fmt.Sprintf("sysctl -w %s=%s", sysctlKey, sysctlVal),
		},
		Metadata:    map[string]string{"sysctl_key": sysctlKey},
		Risk:        model.RiskCritical,
		Impact:      "No new kernel modules can be loaded at runtime until reboot. Required modules must already be loaded. This is a one-way operation at runtime — rollback removes the config file but cannot restore module loading until reboot.",
		Dangerous:   true,
		CanRollback: true,
		Applicable:  true,
		Tags:        []string{"network-safe"},
	}, nil
}

func (m *Module) Apply(ctx context.Context, action *model.PlannedAction, exec executor.Executor) (*model.AppliedAction, error) {
	if err := exec.WriteFile(ctx, ConfPath, []byte(confContent), 0644); err != nil {
		return nil, fmt.Errorf("kernel-modules-disabled: writing %s: %w", ConfPath, err)
	}
	if err := exec.SetSysctl(ctx, sysctlKey, sysctlVal); err != nil {
		return nil, fmt.Errorf("kernel-modules-disabled: setting %s: %w", sysctlKey, err)
	}

	return &model.AppliedAction{
		PlannedAction: *action,
		AppliedAt:     time.Now(),
		Status:        model.ActionApplied,
	}, nil
}

func (m *Module) Validate(ctx context.Context, _ *model.PlannedAction, inspect executor.Inspector) error {
	current, err := inspect.GetSysctl(ctx, sysctlKey)
	if err != nil {
		return fmt.Errorf("kernel-modules-disabled: reading %s: %w", sysctlKey, err)
	}
	if strings.TrimSpace(current) != sysctlVal {
		return fmt.Errorf("kernel-modules-disabled: %s = %q, want %q", sysctlKey, current, sysctlVal)
	}
	return nil
}

func (m *Module) Rollback(ctx context.Context, entry *model.RollbackEntry, exec executor.Executor) error {
	switch entry.Kind {
	case model.RollbackFile:
		if err := exec.WriteFile(ctx, entry.Path, []byte(""), 0644); err != nil {
			return fmt.Errorf("kernel-modules-disabled: clearing %s: %w", entry.Path, err)
		}
		return nil
	case model.RollbackSysctl:
		return nil
	default:
		return fmt.Errorf("kernel-modules-disabled rollback: unexpected kind %q", entry.Kind)
	}
}
