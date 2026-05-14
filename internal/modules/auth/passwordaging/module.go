package passwordaging

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/maestroi/hardener/internal/executor"
	"github.com/maestroi/hardener/internal/model"
	"github.com/maestroi/hardener/internal/modules"
)

const loginDefs = "/etc/login.defs"

type policy struct {
	key   string
	value string
	re    *regexp.Regexp
}

var requiredPolicies = []policy{
	{key: "PASS_MAX_DAYS", value: "90", re: regexp.MustCompile(`(?m)^(\s*PASS_MAX_DAYS\s+)\S+`)},
	{key: "PASS_MIN_DAYS", value: "1", re: regexp.MustCompile(`(?m)^(\s*PASS_MIN_DAYS\s+)\S+`)},
	{key: "PASS_WARN_AGE", value: "14", re: regexp.MustCompile(`(?m)^(\s*PASS_WARN_AGE\s+)\S+`)},
}

// Module remediates AUTH-9286 by enforcing password aging policy in /etc/login.defs.
type Module struct{}

func New() *Module { return &Module{} }

func (m *Module) Metadata() modules.ModuleMetadata {
	return modules.ModuleMetadata{
		ID:               "auth-password-aging",
		Name:             "Password Aging Policy",
		Description:      "Sets PASS_MAX_DAYS=90, PASS_MIN_DAYS=1, PASS_WARN_AGE=14 in /etc/login.defs",
		Category:         "Authentication",
		DefaultRisk:      model.RiskLow,
		SupportedDistros: []string{"ubuntu"},
		Tags:             []string{"network-safe", "docker-safe"},
		CanRollback:      true,
		RequiresReboot:   false,
	}
}

func (m *Module) SupportedFindings() []string {
	return []string{"AUTH-9286"}
}

// missingPolicies returns the list of policies that do not match the required values.
func missingPolicies(content string) []policy {
	var missing []policy
	for _, p := range requiredPolicies {
		lineRe := regexp.MustCompile(`(?m)^` + p.key + `\s+(\S+)`)
		matches := lineRe.FindStringSubmatch(content)
		if len(matches) < 2 || strings.TrimSpace(matches[1]) != p.value {
			missing = append(missing, p)
		}
	}
	return missing
}

// applyPolicies replaces or appends each policy line in content.
func applyPolicies(content string, policies []policy) string {
	for _, p := range policies {
		replacement := p.key + "\t" + p.value
		if p.re.MatchString(content) {
			content = p.re.ReplaceAllString(content, replacement)
		} else {
			content = content + "\n" + replacement + "\n"
		}
	}
	return content
}

// Plan reads login.defs and returns applicable if any aging policy diverges.
func (m *Module) Plan(ctx context.Context, finding *model.Finding, _ *model.Profile, inspect executor.Inspector) (*model.PlannedAction, error) {
	meta := m.Metadata()

	raw, err := inspect.ReadFile(ctx, loginDefs)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", loginDefs, err)
	}

	missing := missingPolicies(string(raw))
	if len(missing) == 0 {
		return &model.PlannedAction{
			FindingID:  finding.ID,
			ModuleID:   meta.ID,
			Applicable: false,
			SkipReason: fmt.Sprintf("%s: password aging policy already meets requirements", loginDefs),
		}, nil
	}

	steps := make([]string, len(missing))
	for i, p := range missing {
		steps[i] = fmt.Sprintf("Set %s = %s in %s", p.key, p.value, loginDefs)
	}

	return &model.PlannedAction{
		FindingID:   finding.ID,
		ModuleID:    meta.ID,
		Title:       "Enforce password aging policy",
		Description: fmt.Sprintf("Set PASS_MAX_DAYS=90, PASS_MIN_DAYS=1, PASS_WARN_AGE=14 in %s", loginDefs),
		Steps:       steps,
		Metadata:    map[string]string{"target_file": loginDefs},
		Risk:        model.RiskLow,
		CanRollback: true,
		Applicable:  true,
		Tags:        []string{"network-safe", "docker-safe"},
	}, nil
}

// Apply sets the password aging policy values in login.defs.
func (m *Module) Apply(ctx context.Context, action *model.PlannedAction, exec executor.Executor) (*model.AppliedAction, error) {
	raw, err := exec.ReadFile(ctx, loginDefs)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", loginDefs, err)
	}

	missing := missingPolicies(string(raw))
	updated := applyPolicies(string(raw), missing)

	if err := exec.WriteFile(ctx, loginDefs, []byte(updated), 0o644); err != nil {
		return nil, fmt.Errorf("writing %s: %w", loginDefs, err)
	}

	return &model.AppliedAction{
		PlannedAction: *action,
		AppliedAt:     time.Now(),
		Status:        model.ActionApplied,
	}, nil
}

// Validate re-reads login.defs and confirms all three policy values are present.
func (m *Module) Validate(ctx context.Context, _ *model.PlannedAction, inspect executor.Inspector) error {
	raw, err := inspect.ReadFile(ctx, loginDefs)
	if err != nil {
		return fmt.Errorf("reading %s for validation: %w", loginDefs, err)
	}
	if missing := missingPolicies(string(raw)); len(missing) > 0 {
		return fmt.Errorf("validation failed: %d aging policy value(s) still incorrect in %s", len(missing), loginDefs)
	}
	return nil
}

// Rollback restores login.defs from the backup recorded in the rollback entry.
func (m *Module) Rollback(ctx context.Context, entry *model.RollbackEntry, exec executor.Executor) error {
	if entry.Kind != model.RollbackFile {
		return fmt.Errorf("auth-password-aging rollback: unexpected kind %q", entry.Kind)
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
