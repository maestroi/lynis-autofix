package pamhistory

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"time"

	"github.com/maestroi/hardener/internal/executor"
	"github.com/maestroi/hardener/internal/model"
	"github.com/maestroi/hardener/internal/modules"
)

const (
	commonPassword = "/etc/pam.d/common-password"
	minRemember    = 5
)

// pamUnixRe matches the pam_unix.so line in common-password.
var pamUnixRe = regexp.MustCompile(`(?m)^(.*pam_unix\.so.*)$`)

// rememberRe extracts the current remember= value.
var rememberRe = regexp.MustCompile(`remember=(\d+)`)

// Module remediates AUTH-9229 by adding remember=5 to the pam_unix.so line.
type Module struct{}

func New() *Module { return &Module{} }

func (m *Module) Metadata() modules.ModuleMetadata {
	return modules.ModuleMetadata{
		ID:               "auth-pam-history",
		Name:             "PAM Password History",
		Description:      "Adds remember=5 to pam_unix.so in /etc/pam.d/common-password",
		Category:         "Authentication",
		DefaultRisk:      model.RiskMedium,
		SupportedDistros: []string{"ubuntu"},
		Tags:             []string{"network-safe", "docker-safe"},
		CanRollback:      true,
		RequiresReboot:   false,
	}
}

func (m *Module) SupportedFindings() []string {
	return []string{"AUTH-9229"}
}

// needsRemember returns true when the pam_unix.so line lacks remember>= minRemember.
func needsRemember(content string) bool {
	match := pamUnixRe.FindString(content)
	if match == "" {
		return true // no pam_unix line — still applicable
	}
	sub := rememberRe.FindStringSubmatch(match)
	if len(sub) < 2 {
		return true
	}
	n, err := strconv.Atoi(sub[1])
	if err != nil {
		return true
	}
	return n < minRemember
}

// addRemember replaces or inserts remember=5 on the pam_unix.so line.
func addRemember(content string) string {
	return pamUnixRe.ReplaceAllStringFunc(content, func(line string) string {
		if rememberRe.MatchString(line) {
			return rememberRe.ReplaceAllString(line, fmt.Sprintf("remember=%d", minRemember))
		}
		return line + fmt.Sprintf(" remember=%d", minRemember)
	})
}

// Plan reads common-password and checks whether remember=5 (or higher) is present.
func (m *Module) Plan(ctx context.Context, finding *model.Finding, _ *model.Profile, inspect executor.Inspector) (*model.PlannedAction, error) {
	meta := m.Metadata()

	raw, err := inspect.ReadFile(ctx, commonPassword)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", commonPassword, err)
	}

	if !needsRemember(string(raw)) {
		return &model.PlannedAction{
			FindingID:  finding.ID,
			ModuleID:   meta.ID,
			Applicable: false,
			SkipReason: fmt.Sprintf("%s: pam_unix.so already has remember>=%d", commonPassword, minRemember),
		}, nil
	}

	return &model.PlannedAction{
		FindingID:   finding.ID,
		ModuleID:    meta.ID,
		Title:       "Enforce password history via PAM",
		Description: fmt.Sprintf("Add remember=%d to pam_unix.so in %s", minRemember, commonPassword),
		Steps:       []string{fmt.Sprintf("Add remember=%d to pam_unix.so line in %s", minRemember, commonPassword)},
		Metadata:    map[string]string{"target_file": commonPassword},
		Risk:        model.RiskMedium,
		CanRollback: true,
		Applicable:  true,
		Tags:        []string{"network-safe", "docker-safe"},
	}, nil
}

// Apply writes the updated common-password with remember=5 on the pam_unix.so line.
func (m *Module) Apply(ctx context.Context, action *model.PlannedAction, exec executor.Executor) (*model.AppliedAction, error) {
	raw, err := exec.ReadFile(ctx, commonPassword)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", commonPassword, err)
	}

	updated := addRemember(string(raw))

	if err := exec.WriteFile(ctx, commonPassword, []byte(updated), 0o644); err != nil {
		return nil, fmt.Errorf("writing %s: %w", commonPassword, err)
	}

	return &model.AppliedAction{
		PlannedAction: *action,
		AppliedAt:     time.Now(),
		Status:        model.ActionApplied,
	}, nil
}

// Validate re-reads common-password and confirms remember>=5 is present.
func (m *Module) Validate(ctx context.Context, _ *model.PlannedAction, inspect executor.Inspector) error {
	raw, err := inspect.ReadFile(ctx, commonPassword)
	if err != nil {
		return fmt.Errorf("reading %s for validation: %w", commonPassword, err)
	}
	if needsRemember(string(raw)) {
		return fmt.Errorf("validation failed: remember>=%d not found in pam_unix.so line of %s", minRemember, commonPassword)
	}
	return nil
}

// Rollback restores common-password from backup.
func (m *Module) Rollback(ctx context.Context, entry *model.RollbackEntry, exec executor.Executor) error {
	if entry.Kind != model.RollbackFile {
		return fmt.Errorf("auth-pam-history rollback: unexpected kind %q", entry.Kind)
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
