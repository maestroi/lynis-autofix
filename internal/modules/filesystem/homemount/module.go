package homemount

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

const FstabPath = "/etc/fstab"

type Module struct{}

func New() *Module { return &Module{} }

func (m *Module) Metadata() modules.ModuleMetadata {
	return modules.ModuleMetadata{
		ID:               "filesystem-homemount",
		Name:             "Secure /home Mount Options",
		Description:      "Adds nodev to the /home fstab entry to prevent device files in home directories",
		Category:         "Filesystem",
		DefaultRisk:      model.RiskHigh,
		SupportedDistros: []string{"ubuntu"},
		Tags:             []string{"network-safe"},
		CanRollback:      true,
		RequiresReboot:   true,
	}
}

func (m *Module) SupportedFindings() []string {
	return []string{"FILE-7524"}
}

func (m *Module) Plan(ctx context.Context, finding *model.Finding, _ *model.Profile, inspect executor.Inspector) (*model.PlannedAction, error) {
	meta := m.Metadata()

	content, err := inspect.ReadFile(ctx, FstabPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("filesystem-homemount: reading %s: %w", FstabPath, err)
	}

	fstab := string(content)

	if !hasFstabEntry(fstab, "/home") {
		return &model.PlannedAction{
			FindingID:  finding.ID,
			ModuleID:   meta.ID,
			Applicable: false,
			SkipReason: "manual prerequisite required: no /home entry in fstab; add a dedicated /home mount before enabling nodev",
		}, nil
	}

	if hasMountOption(fstab, "/home", "nodev") {
		return &model.PlannedAction{
			FindingID:  finding.ID,
			ModuleID:   meta.ID,
			Applicable: false,
			SkipReason: "already compliant: /home already has nodev in fstab",
		}, nil
	}

	return &model.PlannedAction{
		FindingID:      finding.ID,
		ModuleID:       meta.ID,
		Title:          "Add nodev to /home fstab entry",
		Description:    fmt.Sprintf("Modify %s to add nodev to /home mount options", FstabPath),
		Steps:          []string{fmt.Sprintf("backup and rewrite %s with nodev on /home", FstabPath)},
		Metadata:       map[string]string{"target_file": FstabPath},
		Risk:           model.RiskHigh,
		Impact:         "Device files cannot be created in /home. Requires reboot to take effect.",
		Dangerous:      true,
		RequiresReboot: true,
		CanRollback:    true,
		Applicable:     true,
		Tags:           []string{"network-safe"},
	}, nil
}

func (m *Module) Apply(ctx context.Context, action *model.PlannedAction, exec executor.Executor) (*model.AppliedAction, error) {
	content, err := exec.ReadFile(ctx, FstabPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("filesystem-homemount: reading %s: %w", FstabPath, err)
	}

	updated := addFstabOption(string(content), "/home", "nodev")
	if err := exec.WriteFile(ctx, FstabPath, []byte(updated), 0644); err != nil {
		return nil, fmt.Errorf("filesystem-homemount: writing %s: %w", FstabPath, err)
	}

	return &model.AppliedAction{
		PlannedAction: *action,
		AppliedAt:     time.Now(),
		Status:        model.ActionApplied,
	}, nil
}

func (m *Module) Validate(ctx context.Context, _ *model.PlannedAction, inspect executor.Inspector) error {
	content, err := inspect.ReadFile(ctx, FstabPath)
	if err != nil {
		return fmt.Errorf("filesystem-homemount: reading %s: %w", FstabPath, err)
	}
	if !hasMountOption(string(content), "/home", "nodev") {
		return fmt.Errorf("filesystem-homemount: /home is missing nodev in %s", FstabPath)
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
			return fmt.Errorf("filesystem-homemount: reading backup %s: %w", entry.BackupPath, err)
		}
		return exec.WriteFile(ctx, entry.Path, backup, entry.OrigMode)
	default:
		return fmt.Errorf("filesystem-homemount rollback: unexpected kind %q", entry.Kind)
	}
}

func hasFstabEntry(fstab, mountpoint string) bool {
	for _, line := range strings.Split(fstab, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && !strings.HasPrefix(fields[0], "#") && fields[1] == mountpoint {
			return true
		}
	}
	return false
}

func hasMountOption(fstab, mountpoint, opt string) bool {
	for _, line := range strings.Split(fstab, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 || strings.HasPrefix(fields[0], "#") || fields[1] != mountpoint {
			continue
		}
		return strings.Contains(fields[3], opt)
	}
	return false
}

func addFstabOption(fstab, mountpoint, opt string) string {
	lines := strings.Split(fstab, "\n")
	for i, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 4 || strings.HasPrefix(fields[0], "#") || fields[1] != mountpoint {
			continue
		}
		if !strings.Contains(fields[3], opt) {
			fields[3] += "," + opt
		}
		lines[i] = strings.Join(fields, "\t")
	}
	return strings.Join(lines, "\n")
}
