package ssh

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/maestroi/hardener/internal/executor"
	"github.com/maestroi/hardener/internal/model"
	"github.com/maestroi/hardener/internal/modules"
)

// HardeningModule remediates SSH-7408 and SSH-7902 findings.
// It is stateless — no shared state between Plan/Apply/Validate/Rollback.
type HardeningModule struct{}

// New returns a new HardeningModule.
func New() *HardeningModule {
	return &HardeningModule{}
}

func (m *HardeningModule) Metadata() modules.ModuleMetadata {
	return modules.ModuleMetadata{
		ID:               "ssh-hardening",
		Name:             "SSH Hardening",
		Description:      "Applies secure defaults to /etc/ssh/sshd_config and restarts sshd",
		Category:         "SSH",
		DefaultRisk:      model.RiskMedium,
		SupportedDistros: []string{"ubuntu"},
		Tags:             []string{"network-safe"},
		CanRollback:      true,
		RequiresReboot:   false,
	}
}

func (m *HardeningModule) SupportedFindings() []string {
	return []string{"SSH-7408", "SSH-7902"}
}

// Plan reads sshd_config and returns what Apply would change.
// Returns Applicable=false if all required directives already match.
func (m *HardeningModule) Plan(ctx context.Context, finding *model.Finding, _ *model.Profile, inspect executor.Inspector) (*model.PlannedAction, error) {
	meta := m.Metadata()
	content, err := inspect.ReadFile(ctx, ConfigPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &model.PlannedAction{
				FindingID:  finding.ID,
				ModuleID:   meta.ID,
				Applicable: false,
				SkipReason: fmt.Sprintf("%s not found — install OpenSSH server or ensure sshd_config exists", ConfigPath),
			}, nil
		}
		return nil, fmt.Errorf("reading %s: %w", ConfigPath, err)
	}

	needed := missingOrWrongDirectives(string(content), requiredDirectives(finding.ID))
	if len(needed) == 0 {
		return &model.PlannedAction{
			FindingID:  finding.ID,
			ModuleID:   meta.ID,
			Applicable: false,
			SkipReason: fmt.Sprintf("%s: all required SSH directives already set", ConfigPath),
		}, nil
	}

	steps := make([]string, len(needed))
	for i, d := range needed {
		steps[i] = d.humanDescription
	}

	return &model.PlannedAction{
		FindingID:   finding.ID,
		ModuleID:    meta.ID,
		Title:       "Harden SSH configuration",
		Description: fmt.Sprintf("Set %d missing/incorrect directives in %s and restart sshd", len(needed), ConfigPath),
		Steps:       steps,
		Metadata: map[string]string{
			"target_file":  ConfigPath,
			"change_count": strconv.Itoa(len(needed)),
		},
		Risk:        model.RiskMedium,
		Impact:      "Restarts sshd. Existing SSH sessions are preserved.",
		CanRollback: true,
		Applicable:  true,
		Tags:        []string{"network-safe"},
	}, nil
}

// Apply writes the hardened config and restarts sshd.
// Runs sshd -t as a mutation guard before restarting.
func (m *HardeningModule) Apply(ctx context.Context, action *model.PlannedAction, exec executor.Executor) (*model.AppliedAction, error) {
	content, err := exec.ReadFile(ctx, ConfigPath)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", ConfigPath, err)
	}

	directives := requiredDirectives(action.FindingID)
	updated := applyDirectives(string(content), directives)

	info, err := exec.RunReadOnly(ctx, "stat", "-c", "%a", ConfigPath)
	mode := 0644 // fallback if stat fails
	if err == nil {
		if parsed := parseModeFromStat(info.Stdout); parsed != 0 {
			mode = parsed
		}
	}

	if err := exec.WriteFile(ctx, ConfigPath, []byte(updated), octalMode(mode)); err != nil {
		return nil, fmt.Errorf("writing %s: %w", ConfigPath, err)
	}

	if out, err := exec.Run(ctx, "sshd", "-t"); err != nil {
		return nil, fmt.Errorf("sshd config invalid after write (%s): manual review required", out.Stderr)
	}

	if err := exec.RestartService(ctx, "ssh"); err != nil {
		return nil, fmt.Errorf("restarting sshd: %w", err)
	}

	return &model.AppliedAction{
		PlannedAction: *action,
		AppliedAt:     time.Now(),
		Status:        model.ActionApplied,
	}, nil
}

// Validate confirms all required directives are present and sshd is active.
func (m *HardeningModule) Validate(ctx context.Context, action *model.PlannedAction, inspect executor.Inspector) error {
	content, err := inspect.ReadFile(ctx, ConfigPath)
	if err != nil {
		return fmt.Errorf("reading %s for validation: %w", ConfigPath, err)
	}

	needed := missingOrWrongDirectives(string(content), requiredDirectives(action.FindingID))
	if len(needed) > 0 {
		return fmt.Errorf("validation failed: %d directive(s) still missing after apply", len(needed))
	}

	state, err := inspect.ServiceState(ctx, "ssh")
	if err != nil {
		return fmt.Errorf("checking ssh service: %w", err)
	}
	if !state.Active {
		return fmt.Errorf("sshd is not active after apply")
	}
	return nil
}

// Rollback restores the file from backup, validates with sshd -t, then restarts.
func (m *HardeningModule) Rollback(ctx context.Context, entry *model.RollbackEntry, exec executor.Executor) error {
	if entry.Kind != model.RollbackFile {
		return fmt.Errorf("ssh-hardening rollback: unexpected kind %q", entry.Kind)
	}

	backup, err := exec.ReadFile(ctx, entry.BackupPath)
	if err != nil {
		return fmt.Errorf("reading backup at %s: %w", entry.BackupPath, err)
	}

	if err := exec.WriteFile(ctx, entry.Path, backup, entry.OrigMode); err != nil {
		return fmt.Errorf("restoring %s: %w", entry.Path, err)
	}
	if err := exec.SetOwner(ctx, entry.Path, entry.OrigUID, entry.OrigGID); err != nil {
		return fmt.Errorf("restoring ownership of %s: %w", entry.Path, err)
	}

	if out, err := exec.Run(ctx, "sshd", "-t"); err != nil {
		return fmt.Errorf("restored sshd_config failed validation (%s): manual intervention required", out.Stderr)
	}

	return exec.RestartService(ctx, "ssh")
}

func parseModeFromStat(s string) int {
	s = strings.TrimSpace(s)
	var n int
	_, _ = fmt.Sscanf(s, "%o", &n)
	return n
}

func octalMode(n int) fs.FileMode {
	return fs.FileMode(n)
}
