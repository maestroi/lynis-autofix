package sudoers

import (
	"context"
	"fmt"
	"io/fs"
	"strconv"
	"strings"
	"time"

	"github.com/maestroi/hardener/internal/executor"
	"github.com/maestroi/hardener/internal/model"
	"github.com/maestroi/hardener/internal/modules"
)

const (
	sudoersPath  = "/etc/sudoers"
	requiredMode = fs.FileMode(0o440)
)

// Module remediates AUTH-9282 by setting /etc/sudoers to mode 0440.
type Module struct{}

func New() *Module { return &Module{} }

func (m *Module) Metadata() modules.ModuleMetadata {
	return modules.ModuleMetadata{
		ID:               "auth-sudoers-perms",
		Name:             "Sudoers File Permissions",
		Description:      "Ensures /etc/sudoers is owned root:root with mode 0440",
		Category:         "Authentication",
		DefaultRisk:      model.RiskLow,
		SupportedDistros: []string{"ubuntu"},
		Tags:             []string{"network-safe", "docker-safe"},
		CanRollback:      true,
		RequiresReboot:   false,
	}
}

func (m *Module) SupportedFindings() []string {
	return []string{"AUTH-9282"}
}

// parseModeOctal parses the octal string returned by stat -c "%a".
func parseModeOctal(s string) (fs.FileMode, error) {
	s = strings.TrimSpace(s)
	n, err := strconv.ParseUint(s, 8, 32)
	if err != nil {
		return 0, fmt.Errorf("parsing mode %q: %w", s, err)
	}
	return fs.FileMode(n), nil
}

// isMorePermissive returns true when current allows bits not in required.
func isMorePermissive(current, required fs.FileMode) bool {
	return current&^required != 0
}

// Plan stats /etc/sudoers and returns applicable if mode is more permissive than 0440.
func (m *Module) Plan(ctx context.Context, finding *model.Finding, _ *model.Profile, inspect executor.Inspector) (*model.PlannedAction, error) {
	meta := m.Metadata()

	out, err := inspect.RunReadOnly(ctx, "stat", "-c", "%a", sudoersPath)
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", sudoersPath, err)
	}

	current, err := parseModeOctal(out.Stdout)
	if err != nil {
		return nil, fmt.Errorf("parsing mode of %s: %w", sudoersPath, err)
	}

	if !isMorePermissive(current, requiredMode) {
		return &model.PlannedAction{
			FindingID:  finding.ID,
			ModuleID:   meta.ID,
			Applicable: false,
			SkipReason: fmt.Sprintf("already compliant: %s mode %04o is already %04o or more restrictive", sudoersPath, current, requiredMode),
		}, nil
	}

	return &model.PlannedAction{
		FindingID:   finding.ID,
		ModuleID:    meta.ID,
		Title:       "Fix sudoers file permissions",
		Description: fmt.Sprintf("Set %s to mode %04o (currently %04o)", sudoersPath, requiredMode, current),
		Steps:       []string{fmt.Sprintf("chmod %04o %s", requiredMode, sudoersPath)},
		Metadata: map[string]string{
			"target_file":   sudoersPath,
			"current_mode":  fmt.Sprintf("%04o", current),
			"required_mode": fmt.Sprintf("%04o", requiredMode),
		},
		Risk:        model.RiskLow,
		CanRollback: true,
		Applicable:  true,
		Tags:        []string{"network-safe", "docker-safe"},
	}, nil
}

// Apply sets /etc/sudoers to mode 0440.
func (m *Module) Apply(ctx context.Context, action *model.PlannedAction, exec executor.Executor) (*model.AppliedAction, error) {
	if err := exec.SetFileMode(ctx, sudoersPath, requiredMode); err != nil {
		return nil, fmt.Errorf("setting mode on %s: %w", sudoersPath, err)
	}
	return &model.AppliedAction{
		PlannedAction: *action,
		AppliedAt:     time.Now(),
		Status:        model.ActionApplied,
	}, nil
}

// Validate re-stats /etc/sudoers and confirms mode is 440 or more restrictive.
func (m *Module) Validate(ctx context.Context, _ *model.PlannedAction, inspect executor.Inspector) error {
	out, err := inspect.RunReadOnly(ctx, "stat", "-c", "%a", sudoersPath)
	if err != nil {
		return fmt.Errorf("stat %s: %w", sudoersPath, err)
	}
	current, err := parseModeOctal(out.Stdout)
	if err != nil {
		return fmt.Errorf("parsing mode of %s: %w", sudoersPath, err)
	}
	if isMorePermissive(current, requiredMode) {
		return fmt.Errorf("validation failed: %s mode is %04o, expected %04o or more restrictive", sudoersPath, current, requiredMode)
	}
	return nil
}

// Rollback restores sudoers from backup (file content) and resets the original mode.
func (m *Module) Rollback(ctx context.Context, entry *model.RollbackEntry, exec executor.Executor) error {
	if entry.Kind != model.RollbackFile {
		return fmt.Errorf("auth-sudoers-perms rollback: unexpected kind %q", entry.Kind)
	}
	backup, err := exec.ReadFile(ctx, entry.BackupPath)
	if err != nil {
		return fmt.Errorf("reading backup at %s: %w", entry.BackupPath, err)
	}
	if err := exec.WriteFile(ctx, entry.Path, backup, entry.OrigMode); err != nil {
		return fmt.Errorf("restoring %s: %w", entry.Path, err)
	}
	return exec.SetOwner(ctx, entry.Path, entry.OrigUID, entry.OrigGID)
}
