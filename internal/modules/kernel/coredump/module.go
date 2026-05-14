package coredump

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/maestroi/hardener/internal/executor"
	"github.com/maestroi/hardener/internal/model"
	"github.com/maestroi/hardener/internal/modules"
)

const (
	LimitsPath        = "/etc/security/limits.conf"
	LimitsLine        = "* hard core 0"
	SuidDumpableKey   = "fs.suid_dumpable"
	SuidDumpableValue = "0"
)

type Module struct{}

func New() *Module {
	return &Module{}
}

func (m *Module) Metadata() modules.ModuleMetadata {
	return modules.ModuleMetadata{
		ID:               "kernel-coredump",
		Name:             "Kernel Core Dump Restriction",
		Description:      "Prevents core dump creation by setting limits.conf and fs.suid_dumpable=0",
		Category:         "Kernel",
		DefaultRisk:      model.RiskLow,
		SupportedDistros: []string{"ubuntu"},
		Tags:             []string{"network-safe", "docker-safe"},
		CanRollback:      true,
		RequiresReboot:   false,
	}
}

func (m *Module) SupportedFindings() []string {
	return []string{"KRNL-5820"}
}

func (m *Module) Plan(ctx context.Context, finding *model.Finding, _ *model.Profile, inspect executor.Inspector) (*model.PlannedAction, error) {
	meta := m.Metadata()

	limitsOK := false
	content, err := inspect.ReadFile(ctx, LimitsPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("reading %s: %w", LimitsPath, err)
	}
	if err == nil {
		limitsOK = strings.Contains(string(content), LimitsLine)
	}

	current, err := inspect.GetSysctl(ctx, SuidDumpableKey)
	if err != nil {
		return nil, fmt.Errorf("reading sysctl %s: %w", SuidDumpableKey, err)
	}
	sysctlOK := strings.TrimSpace(current) == SuidDumpableValue

	if limitsOK && sysctlOK {
		return &model.PlannedAction{
			FindingID:  finding.ID,
			ModuleID:   meta.ID,
			Applicable: false,
			SkipReason: fmt.Sprintf("%s already contains %q and %s is already %s", LimitsPath, LimitsLine, SuidDumpableKey, SuidDumpableValue),
		}, nil
	}

	var steps []string
	if !limitsOK {
		steps = append(steps, fmt.Sprintf("append %q to %s", LimitsLine, LimitsPath))
	}
	if !sysctlOK {
		steps = append(steps, fmt.Sprintf("set %s = %s", SuidDumpableKey, SuidDumpableValue))
	}

	return &model.PlannedAction{
		FindingID:   finding.ID,
		ModuleID:    meta.ID,
		Title:       "Restrict core dumps",
		Description: fmt.Sprintf("Disable core dump generation via %s and sysctl %s", LimitsPath, SuidDumpableKey),
		Steps:       steps,
		Metadata: map[string]string{
			"target_file": LimitsPath,
			"sysctl_key":  SuidDumpableKey,
		},
		Risk:        model.RiskLow,
		Impact:      "Prevents core dumps system-wide. Debugging of crashes will require explicit re-enablement.",
		CanRollback: true,
		Applicable:  true,
		Tags:        []string{"network-safe", "docker-safe"},
	}, nil
}

func (m *Module) Apply(ctx context.Context, action *model.PlannedAction, exec executor.Executor) (*model.AppliedAction, error) {
	content, err := exec.ReadFile(ctx, LimitsPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("reading %s: %w", LimitsPath, err)
	}

	if !strings.Contains(string(content), LimitsLine) {
		appendContent := []byte("\n" + LimitsLine + "\n")
		if err := exec.AppendFile(ctx, LimitsPath, appendContent); err != nil {
			return nil, fmt.Errorf("appending to %s: %w", LimitsPath, err)
		}
	}

	if err := exec.SetSysctl(ctx, SuidDumpableKey, SuidDumpableValue); err != nil {
		return nil, fmt.Errorf("setting %s: %w", SuidDumpableKey, err)
	}

	return &model.AppliedAction{
		PlannedAction: *action,
		AppliedAt:     time.Now(),
		Status:        model.ActionApplied,
	}, nil
}

func (m *Module) Validate(ctx context.Context, _ *model.PlannedAction, inspect executor.Inspector) error {
	content, err := inspect.ReadFile(ctx, LimitsPath)
	if err != nil {
		return fmt.Errorf("reading %s for validation: %w", LimitsPath, err)
	}
	if !strings.Contains(string(content), LimitsLine) {
		return fmt.Errorf("validation failed: %q not found in %s", LimitsLine, LimitsPath)
	}

	current, err := inspect.GetSysctl(ctx, SuidDumpableKey)
	if err != nil {
		return fmt.Errorf("reading sysctl %s for validation: %w", SuidDumpableKey, err)
	}
	if strings.TrimSpace(current) != SuidDumpableValue {
		return fmt.Errorf("validation failed: %s = %q, want %q", SuidDumpableKey, current, SuidDumpableValue)
	}

	return nil
}

func (m *Module) Rollback(ctx context.Context, entry *model.RollbackEntry, exec executor.Executor) error {
	switch entry.Kind {
	case model.RollbackFile:
		backup, err := exec.ReadFile(ctx, entry.BackupPath)
		if err != nil {
			return fmt.Errorf("reading backup at %s: %w", entry.BackupPath, err)
		}
		if err := exec.WriteFile(ctx, entry.Path, backup, entry.OrigMode); err != nil {
			return fmt.Errorf("restoring %s: %w", entry.Path, err)
		}
		return nil

	case model.RollbackSysctl:
		return nil

	default:
		return fmt.Errorf("kernel-coredump rollback: unexpected kind %q", entry.Kind)
	}
}
