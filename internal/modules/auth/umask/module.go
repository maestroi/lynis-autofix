package umask

import (
	"context"
	"fmt"
	"regexp"
	"time"

	"github.com/maestroi/hardener/internal/executor"
	"github.com/maestroi/hardener/internal/model"
	"github.com/maestroi/hardener/internal/modules"
)

const (
	loginDefs     = "/etc/login.defs"
	requiredUmask = "027"
)

// activeUmaskRe matches an uncommented UMASK line with any value.
var activeUmaskRe = regexp.MustCompile(`(?m)^(\s*UMASK\s+)\S+`)

// correctUmaskRe matches an uncommented UMASK line already set to 027.
var correctUmaskRe = regexp.MustCompile(`(?m)^\s*UMASK\s+027\s*$`)

// Module remediates AUTH-9328 by setting UMASK 027 in /etc/login.defs.
type Module struct{}

func New() *Module { return &Module{} }

func (m *Module) Metadata() modules.ModuleMetadata {
	return modules.ModuleMetadata{
		ID:               "auth-umask",
		Name:             "Default Umask Policy",
		Description:      "Sets UMASK 027 in /etc/login.defs for restrictive default file permissions",
		Category:         "Authentication",
		DefaultRisk:      model.RiskLow,
		SupportedDistros: []string{"ubuntu"},
		Tags:             []string{"network-safe", "docker-safe"},
		CanRollback:      true,
		RequiresReboot:   false,
	}
}

func (m *Module) SupportedFindings() []string {
	return []string{"AUTH-9328"}
}

// Plan reads login.defs and checks whether UMASK is already set to 027.
func (m *Module) Plan(ctx context.Context, finding *model.Finding, _ *model.Profile, inspect executor.Inspector) (*model.PlannedAction, error) {
	meta := m.Metadata()

	raw, err := inspect.ReadFile(ctx, loginDefs)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", loginDefs, err)
	}

	if correctUmaskRe.Match(raw) {
		return &model.PlannedAction{
			FindingID:  finding.ID,
			ModuleID:   meta.ID,
			Applicable: false,
			SkipReason: fmt.Sprintf("%s: UMASK is already set to 027", loginDefs),
		}, nil
	}

	return &model.PlannedAction{
		FindingID:   finding.ID,
		ModuleID:    meta.ID,
		Title:       "Set default umask to 027",
		Description: fmt.Sprintf("Set UMASK 027 in %s", loginDefs),
		Steps:       []string{fmt.Sprintf("Set UMASK = 027 in %s", loginDefs)},
		Metadata:    map[string]string{"target_file": loginDefs},
		Risk:        model.RiskLow,
		CanRollback: true,
		Applicable:  true,
		Tags:        []string{"network-safe", "docker-safe"},
	}, nil
}

// Apply sets UMASK 027 in login.defs, replacing an existing line or appending.
func (m *Module) Apply(ctx context.Context, action *model.PlannedAction, exec executor.Executor) (*model.AppliedAction, error) {
	raw, err := exec.ReadFile(ctx, loginDefs)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", loginDefs, err)
	}

	content := string(raw)
	newLine := "UMASK\t\t" + requiredUmask
	if activeUmaskRe.MatchString(content) {
		content = activeUmaskRe.ReplaceAllString(content, newLine)
	} else {
		content = content + "\n" + newLine + "\n"
	}

	if err := exec.WriteFile(ctx, loginDefs, []byte(content), 0o644); err != nil {
		return nil, fmt.Errorf("writing %s: %w", loginDefs, err)
	}

	return &model.AppliedAction{
		PlannedAction: *action,
		AppliedAt:     time.Now(),
		Status:        model.ActionApplied,
	}, nil
}

// Validate re-reads login.defs and confirms UMASK 027 is present.
func (m *Module) Validate(ctx context.Context, _ *model.PlannedAction, inspect executor.Inspector) error {
	raw, err := inspect.ReadFile(ctx, loginDefs)
	if err != nil {
		return fmt.Errorf("reading %s for validation: %w", loginDefs, err)
	}
	if !correctUmaskRe.Match(raw) {
		return fmt.Errorf("validation failed: UMASK 027 not found in %s", loginDefs)
	}
	return nil
}

// Rollback restores login.defs from backup.
func (m *Module) Rollback(ctx context.Context, entry *model.RollbackEntry, exec executor.Executor) error {
	if entry.Kind != model.RollbackFile {
		return fmt.Errorf("auth-umask rollback: unexpected kind %q", entry.Kind)
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
