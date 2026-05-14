package usbstorage

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
	ConfPath = "/etc/modprobe.d/usb-storage.conf"

	ConfContent = `# Managed by hardener — do not edit manually.
install usb-storage /bin/true
blacklist usb-storage
`
)

type Module struct{}

func New() *Module { return &Module{} }

func (m *Module) Metadata() modules.ModuleMetadata {
	return modules.ModuleMetadata{
		ID:               "kernel-usb-storage",
		Name:             "Disable USB Storage",
		Description:      "Blacklists the usb-storage kernel module to prevent USB mass storage devices from mounting",
		Category:         "Kernel",
		DefaultRisk:      model.RiskMedium,
		SupportedDistros: []string{"ubuntu"},
		Tags:             []string{"network-safe"},
		CanRollback:      true,
		RequiresReboot:   true,
	}
}

func (m *Module) SupportedFindings() []string {
	return []string{"USB-1000", "HRDN-7230"}
}

func (m *Module) Plan(ctx context.Context, finding *model.Finding, _ *model.Profile, inspect executor.Inspector) (*model.PlannedAction, error) {
	meta := m.Metadata()

	content, err := inspect.ReadFile(ctx, ConfPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("kernel-usb-storage: reading %s: %w", ConfPath, err)
	}

	if err == nil && strings.Contains(string(content), "blacklist usb-storage") {
		return &model.PlannedAction{
			FindingID:  finding.ID,
			ModuleID:   meta.ID,
			Applicable: false,
			SkipReason: fmt.Sprintf("%s already blacklists usb-storage", ConfPath),
		}, nil
	}

	return &model.PlannedAction{
		FindingID:      finding.ID,
		ModuleID:       meta.ID,
		Title:          "Blacklist USB storage module",
		Description:    fmt.Sprintf("Write %s to disable USB mass storage mounting", ConfPath),
		Steps:          []string{fmt.Sprintf("write %s", ConfPath)},
		Metadata:       map[string]string{"target_file": ConfPath},
		Risk:           model.RiskMedium,
		Impact:         "USB mass storage devices will not mount after reboot. USB input devices (keyboard, mouse) are unaffected.",
		RequiresReboot: true,
		CanRollback:    true,
		Applicable:     true,
		Tags:           []string{"network-safe"},
	}, nil
}

func (m *Module) Apply(ctx context.Context, action *model.PlannedAction, exec executor.Executor) (*model.AppliedAction, error) {
	if err := exec.WriteFile(ctx, ConfPath, []byte(ConfContent), 0644); err != nil {
		return nil, fmt.Errorf("kernel-usb-storage: writing %s: %w", ConfPath, err)
	}
	return &model.AppliedAction{
		PlannedAction: *action,
		AppliedAt:     time.Now(),
		Status:        model.ActionApplied,
	}, nil
}

func (m *Module) Validate(ctx context.Context, _ *model.PlannedAction, inspect executor.Inspector) error {
	content, err := inspect.ReadFile(ctx, ConfPath)
	if err != nil {
		return fmt.Errorf("kernel-usb-storage: reading %s: %w", ConfPath, err)
	}
	if !strings.Contains(string(content), "blacklist usb-storage") {
		return fmt.Errorf("kernel-usb-storage: blacklist entry missing from %s", ConfPath)
	}
	return nil
}

func (m *Module) Rollback(ctx context.Context, entry *model.RollbackEntry, exec executor.Executor) error {
	switch entry.Kind {
	case model.RollbackFile:
		if entry.BackupPath == "" {
			return nil
		}
		backup, err := exec.ReadFile(ctx, entry.BackupPath)
		if err != nil {
			return fmt.Errorf("kernel-usb-storage: reading backup %s: %w", entry.BackupPath, err)
		}
		return exec.WriteFile(ctx, entry.Path, backup, entry.OrigMode)
	default:
		return fmt.Errorf("kernel-usb-storage rollback: unexpected kind %q", entry.Kind)
	}
}
