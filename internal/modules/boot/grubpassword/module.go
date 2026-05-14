package grubpassword

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

const ScriptPath = "/etc/grub.d/01-hardener-password"

type Module struct{}

func New() *Module { return &Module{} }

func (m *Module) Metadata() modules.ModuleMetadata {
	return modules.ModuleMetadata{
		ID:               "boot-grub-password",
		Name:             "Set GRUB Bootloader Password",
		Description:      "Writes a GRUB password script so the bootloader requires authentication before editing entries",
		Category:         "Boot",
		DefaultRisk:      model.RiskCritical,
		SupportedDistros: []string{"ubuntu"},
		Tags:             []string{"network-safe"},
		CanRollback:      true,
		RequiresReboot:   false,
	}
}

func (m *Module) SupportedFindings() []string {
	return []string{"BOOT-5122"}
}

func (m *Module) Plan(ctx context.Context, finding *model.Finding, profile *model.Profile, inspect executor.Inspector) (*model.PlannedAction, error) {
	meta := m.Metadata()

	if profile.GrubPasswordHash == "" {
		return &model.PlannedAction{
			FindingID:  finding.ID,
			ModuleID:   meta.ID,
			Applicable: false,
			SkipReason: "blocked by policy/config: set grub_password_hash in profile to enable BOOT-5122 remediation (generate with: grub-mkpasswd-pbkdf2)",
		}, nil
	}

	content, err := inspect.ReadFile(ctx, ScriptPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("boot-grub-password: reading %s: %w", ScriptPath, err)
	}

	if err == nil && strings.Contains(string(content), profile.GrubPasswordHash) {
		return &model.PlannedAction{
			FindingID:  finding.ID,
			ModuleID:   meta.ID,
			Applicable: false,
			SkipReason: fmt.Sprintf("already compliant: %s already contains the configured password hash", ScriptPath),
		}, nil
	}

	return &model.PlannedAction{
		FindingID:   finding.ID,
		ModuleID:    meta.ID,
		Title:       "Set GRUB bootloader password",
		Description: fmt.Sprintf("Write %s and run update-grub to protect bootloader entries", ScriptPath),
		Steps: []string{
			fmt.Sprintf("write %s with PBKDF2 hash", ScriptPath),
			"chmod 700 " + ScriptPath,
			"update-grub",
		},
		Metadata:    map[string]string{"hash": profile.GrubPasswordHash},
		Risk:        model.RiskCritical,
		Impact:      "GRUB will require the configured password to edit boot entries or access recovery mode.",
		Dangerous:   true,
		CanRollback: true,
		Applicable:  true,
		Tags:        []string{"network-safe"},
	}, nil
}

func (m *Module) Apply(ctx context.Context, action *model.PlannedAction, exec executor.Executor) (*model.AppliedAction, error) {
	hash := action.Metadata["hash"]
	script := fmt.Sprintf(`#!/bin/sh
# Managed by hardener — do not edit manually.
set superusers="root"
password_pbkdf2 root %s
`, hash)

	if err := exec.WriteFile(ctx, ScriptPath, []byte(script), 0700); err != nil {
		return nil, fmt.Errorf("boot-grub-password: writing %s: %w", ScriptPath, err)
	}
	if err := exec.SetFileMode(ctx, ScriptPath, 0700); err != nil {
		return nil, fmt.Errorf("boot-grub-password: chmod %s: %w", ScriptPath, err)
	}
	if _, err := exec.Run(ctx, "update-grub"); err != nil {
		return nil, fmt.Errorf("boot-grub-password: update-grub: %w", err)
	}

	return &model.AppliedAction{
		PlannedAction: *action,
		AppliedAt:     time.Now(),
		Status:        model.ActionApplied,
	}, nil
}

func (m *Module) Validate(ctx context.Context, action *model.PlannedAction, inspect executor.Inspector) error {
	hash := action.Metadata["hash"]
	content, err := inspect.ReadFile(ctx, ScriptPath)
	if err != nil {
		return fmt.Errorf("boot-grub-password: reading %s: %w", ScriptPath, err)
	}
	if !strings.Contains(string(content), hash) {
		return fmt.Errorf("boot-grub-password: hash not found in %s after apply", ScriptPath)
	}
	return nil
}

func (m *Module) Rollback(ctx context.Context, entry *model.RollbackEntry, exec executor.Executor) error {
	switch entry.Kind {
	case model.RollbackFile:
		if err := exec.WriteFile(ctx, entry.Path, []byte(""), 0700); err != nil {
			return fmt.Errorf("boot-grub-password: clearing %s: %w", entry.Path, err)
		}
		if _, err := exec.Run(ctx, "update-grub"); err != nil {
			return fmt.Errorf("boot-grub-password: update-grub on rollback: %w", err)
		}
		return nil
	default:
		return fmt.Errorf("boot-grub-password rollback: unexpected kind %q", entry.Kind)
	}
}
