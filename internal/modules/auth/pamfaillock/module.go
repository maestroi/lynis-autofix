package pamfaillock

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

const (
	faillockConf = "/etc/security/faillock.conf"
	commonAuth   = "/etc/pam.d/common-auth"
)

type faillockPolicy struct {
	key    string
	value  string
	replRe *regexp.Regexp
}

var requiredPolicies = []faillockPolicy{
	{
		key:    "deny",
		value:  "5",
		replRe: regexp.MustCompile(`(?m)^\s*deny\s*=\s*\S+`),
	},
	{
		key:    "unlock_time",
		value:  "900",
		replRe: regexp.MustCompile(`(?m)^\s*unlock_time\s*=\s*\S+`),
	},
}

// Module remediates AUTH-9230 by writing /etc/security/faillock.conf.
type Module struct{}

func New() *Module { return &Module{} }

func (m *Module) Metadata() modules.ModuleMetadata {
	return modules.ModuleMetadata{
		ID:               "auth-pam-faillock",
		Name:             "Account Lockout (pam_faillock)",
		Description:      "Configures /etc/security/faillock.conf with deny=5 and unlock_time=900",
		Category:         "Authentication",
		DefaultRisk:      model.RiskMedium,
		SupportedDistros: []string{"ubuntu"},
		Tags:             []string{"network-safe", "docker-safe"},
		CanRollback:      true,
		RequiresReboot:   false,
	}
}

func (m *Module) SupportedFindings() []string {
	return []string{"AUTH-9230"}
}

// checkPolicy reads faillock.conf content and returns which policies are missing.
func checkPolicy(content string) []faillockPolicy {
	var missing []faillockPolicy
	for _, p := range requiredPolicies {
		valueRe := regexp.MustCompile(`(?m)^\s*` + p.key + `\s*=\s*(\S+)`)
		matches := valueRe.FindStringSubmatch(content)
		if len(matches) < 2 || strings.TrimSpace(matches[1]) != p.value {
			missing = append(missing, p)
		}
	}
	return missing
}

// applyPolicy writes/updates faillock.conf content with required values.
func applyPolicy(content string, policies []faillockPolicy) string {
	for _, p := range policies {
		line := p.key + " = " + p.value
		if p.replRe.MatchString(content) {
			content = p.replRe.ReplaceAllString(content, line)
		} else {
			content = content + "\n" + line + "\n"
		}
	}
	// Ensure 'silent' is present (no value needed).
	if !regexp.MustCompile(`(?m)^\s*silent\s*$`).MatchString(content) {
		content = content + "\nsilent\n"
	}
	return content
}

// Plan reads or creates faillock.conf and returns applicable if any value is wrong.
func (m *Module) Plan(ctx context.Context, finding *model.Finding, _ *model.Profile, inspect executor.Inspector) (*model.PlannedAction, error) {
	meta := m.Metadata()

	raw, err := inspect.ReadFile(ctx, faillockConf)
	if err != nil {
		// File may not exist on some Ubuntu versions — treat as empty.
		raw = []byte{}
	}

	// Check whether common-auth already references pam_faillock.
	authRaw, authErr := inspect.ReadFile(ctx, commonAuth)
	pamFaillockPresent := authErr == nil && strings.Contains(string(authRaw), "pam_faillock")

	missing := checkPolicy(string(raw))
	if len(missing) == 0 {
		return &model.PlannedAction{
			FindingID:  finding.ID,
			ModuleID:   meta.ID,
			Applicable: false,
			SkipReason: fmt.Sprintf("%s: faillock policy already meets requirements", faillockConf),
		}, nil
	}

	steps := []string{
		fmt.Sprintf("Write deny = 5 in %s", faillockConf),
		fmt.Sprintf("Write unlock_time = 900 in %s", faillockConf),
		fmt.Sprintf("Write silent in %s", faillockConf),
	}
	if !pamFaillockPresent {
		steps = append(steps, fmt.Sprintf("MANUAL: add pam_faillock lines to %s (not automated — too risky)", commonAuth))
	}

	metadata := map[string]string{"target_file": faillockConf}
	if !pamFaillockPresent {
		metadata["manual_pam"] = "true"
	}

	return &model.PlannedAction{
		FindingID:   finding.ID,
		ModuleID:    meta.ID,
		Title:       "Configure account lockout policy",
		Description: fmt.Sprintf("Write deny=5, unlock_time=900, silent to %s", faillockConf),
		Steps:       steps,
		Metadata:    metadata,
		Risk:        model.RiskMedium,
		CanRollback: true,
		Applicable:  true,
		Tags:        []string{"network-safe", "docker-safe"},
	}, nil
}

// Apply writes faillock.conf with the required values.
// Does NOT modify /etc/pam.d/common-auth.
func (m *Module) Apply(ctx context.Context, action *model.PlannedAction, exec executor.Executor) (*model.AppliedAction, error) {
	raw, err := exec.ReadFile(ctx, faillockConf)
	if err != nil {
		raw = []byte{} // create fresh if absent
	}

	missing := checkPolicy(string(raw))
	updated := applyPolicy(string(raw), missing)

	if err := exec.WriteFile(ctx, faillockConf, []byte(updated), 0o644); err != nil {
		return nil, fmt.Errorf("writing %s: %w", faillockConf, err)
	}

	return &model.AppliedAction{
		PlannedAction: *action,
		AppliedAt:     time.Now(),
		Status:        model.ActionApplied,
	}, nil
}

// Validate re-reads faillock.conf and confirms deny=5 and unlock_time=900.
func (m *Module) Validate(ctx context.Context, _ *model.PlannedAction, inspect executor.Inspector) error {
	raw, err := inspect.ReadFile(ctx, faillockConf)
	if err != nil {
		return fmt.Errorf("reading %s for validation: %w", faillockConf, err)
	}
	if missing := checkPolicy(string(raw)); len(missing) > 0 {
		return fmt.Errorf("validation failed: %d faillock policy value(s) still incorrect", len(missing))
	}
	return nil
}

// Rollback restores faillock.conf from backup.
func (m *Module) Rollback(ctx context.Context, entry *model.RollbackEntry, exec executor.Executor) error {
	if entry.Kind != model.RollbackFile {
		return fmt.Errorf("auth-pam-faillock rollback: unexpected kind %q", entry.Kind)
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
