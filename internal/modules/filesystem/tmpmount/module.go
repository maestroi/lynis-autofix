package tmpmount

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

var requiredOptions = []string{"nodev", "nosuid", "noexec"}

type Module struct{}

func New() *Module { return &Module{} }

func (m *Module) Metadata() modules.ModuleMetadata {
	return modules.ModuleMetadata{
		ID:               "filesystem-tmpmount",
		Name:             "Secure /tmp Mount Options",
		Description:      "Adds nodev, nosuid, noexec to the /tmp fstab entry to prevent execution of binaries from /tmp",
		Category:         "Filesystem",
		DefaultRisk:      model.RiskHigh,
		SupportedDistros: []string{"ubuntu"},
		Tags:             []string{"network-safe"},
		CanRollback:      true,
		RequiresReboot:   true,
	}
}

func (m *Module) SupportedFindings() []string {
	return []string{"FILE-6310"}
}

func (m *Module) Plan(ctx context.Context, finding *model.Finding, _ *model.Profile, inspect executor.Inspector) (*model.PlannedAction, error) {
	meta := m.Metadata()

	content, err := inspect.ReadFile(ctx, FstabPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("filesystem-tmpmount: reading %s: %w", FstabPath, err)
	}

	if err == nil && hasMountOptions(string(content), "/tmp", requiredOptions) {
		return &model.PlannedAction{
			FindingID:  finding.ID,
			ModuleID:   meta.ID,
			Applicable: false,
			SkipReason: "/tmp already has nodev, nosuid, noexec in fstab",
		}, nil
	}

	return &model.PlannedAction{
		FindingID:      finding.ID,
		ModuleID:       meta.ID,
		Title:          "Add nodev/nosuid/noexec to /tmp fstab entry",
		Description:    fmt.Sprintf("Modify %s to add security mount options to /tmp", FstabPath),
		Steps: []string{
			fmt.Sprintf("backup and rewrite %s with nodev,nosuid,noexec on /tmp", FstabPath),
		},
		Metadata:       map[string]string{"target_file": FstabPath},
		Risk:           model.RiskHigh,
		Impact:         "Binaries in /tmp cannot be executed and device files cannot be created. Requires reboot to take effect.",
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
		return nil, fmt.Errorf("filesystem-tmpmount: reading %s: %w", FstabPath, err)
	}

	updated := addMountOptions(string(content), "/tmp", "tmpfs", requiredOptions)
	if err := exec.WriteFile(ctx, FstabPath, []byte(updated), 0644); err != nil {
		return nil, fmt.Errorf("filesystem-tmpmount: writing %s: %w", FstabPath, err)
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
		return fmt.Errorf("filesystem-tmpmount: reading %s: %w", FstabPath, err)
	}
	if !hasMountOptions(string(content), "/tmp", requiredOptions) {
		return fmt.Errorf("filesystem-tmpmount: /tmp is missing nodev/nosuid/noexec in %s", FstabPath)
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
			return fmt.Errorf("filesystem-tmpmount: reading backup %s: %w", entry.BackupPath, err)
		}
		return exec.WriteFile(ctx, entry.Path, backup, entry.OrigMode)
	default:
		return fmt.Errorf("filesystem-tmpmount rollback: unexpected kind %q", entry.Kind)
	}
}

// hasMountOptions returns true if the fstab content has all opts on the mountpoint line.
func hasMountOptions(fstab, mountpoint string, opts []string) bool {
	for _, line := range strings.Split(fstab, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 || strings.HasPrefix(fields[0], "#") {
			continue
		}
		if fields[1] != mountpoint {
			continue
		}
		optField := fields[3]
		for _, o := range opts {
			if !strings.Contains(optField, o) {
				return false
			}
		}
		return true
	}
	return false
}

// addMountOptions rewrites fstab to add opts to mountpoint.
// If the mountpoint line is absent, a new tmpfs entry is appended.
func addMountOptions(fstab, mountpoint, fstype string, opts []string) string {
	lines := strings.Split(fstab, "\n")
	found := false
	for i, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 4 || strings.HasPrefix(fields[0], "#") {
			continue
		}
		if fields[1] != mountpoint {
			continue
		}
		found = true
		optField := fields[3]
		for _, o := range opts {
			if !strings.Contains(optField, o) {
				optField += "," + o
			}
		}
		fields[3] = optField
		lines[i] = strings.Join(fields, "\t")
	}
	if !found {
		newLine := fmt.Sprintf("%s\t%s\t%s\tdefaults,%s\t0\t0",
			fstype, mountpoint, fstype, strings.Join(opts, ","))
		lines = append(lines, newLine)
	}
	return strings.Join(lines, "\n")
}
