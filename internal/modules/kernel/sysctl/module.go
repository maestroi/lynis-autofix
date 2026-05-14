package sysctl

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/maestroi/hardener/internal/executor"
	"github.com/maestroi/hardener/internal/model"
	"github.com/maestroi/hardener/internal/modules"
)

// ConfPath is the drop-in file written by this module.
const ConfPath = "/etc/sysctl.d/99-hardener.conf"

// desiredValues lists the sysctl key/value pairs this module enforces.
// Ordered for deterministic file output.
var desiredValues = []sysctlKV{
	{"net.ipv4.conf.all.accept_redirects", "0"},
	{"net.ipv4.conf.default.accept_redirects", "0"},
	{"net.ipv6.conf.all.accept_redirects", "0"},
	{"net.ipv6.conf.default.accept_redirects", "0"},
	{"net.ipv4.conf.all.send_redirects", "0"},
	{"net.ipv4.conf.default.send_redirects", "0"},
	{"net.ipv4.conf.all.accept_source_route", "0"},
	{"net.ipv4.conf.default.accept_source_route", "0"},
	{"net.ipv4.tcp_syncookies", "1"},
	{"net.ipv4.conf.all.log_martians", "1"},
	{"net.ipv4.conf.default.log_martians", "1"},
	{"kernel.dmesg_restrict", "1"},
	{"kernel.kptr_restrict", "2"},
	{"kernel.sysrq", "0"},
	{"kernel.core_uses_pid", "1"},
}

type sysctlKV struct {
	Key   string
	Value string
}

// Module remediates KRNL-6000 findings.
// It is stateless — no shared state between Plan/Apply/Validate/Rollback.
type Module struct{}

// New returns a new sysctl Module.
func New() *Module {
	return &Module{}
}

func (m *Module) Metadata() modules.ModuleMetadata {
	return modules.ModuleMetadata{
		ID:               "kernel-sysctl",
		Name:             "Kernel Sysctl Hardening",
		Description:      "Writes /etc/sysctl.d/99-hardener.conf with secure network and kernel parameters and activates them via sysctl --system",
		Category:         "Kernel",
		DefaultRisk:      model.RiskMedium,
		SupportedDistros: []string{"ubuntu"},
		Tags:             []string{"network-safe"},
		CanRollback:      true,
		RequiresReboot:   false,
	}
}

func (m *Module) SupportedFindings() []string {
	return []string{"KRNL-6000"}
}

// Plan reads current sysctl values and returns what Apply would change.
// Returns Applicable=false if every desired value already matches.
func (m *Module) Plan(ctx context.Context, finding *model.Finding, _ *model.Profile, inspect executor.Inspector) (*model.PlannedAction, error) {
	meta := m.Metadata()

	var needed []sysctlKV
	for _, kv := range desiredValues {
		current, err := inspect.GetSysctl(ctx, kv.Key)
		if err != nil {
			return nil, fmt.Errorf("reading sysctl %s: %w", kv.Key, err)
		}
		if strings.TrimSpace(current) != kv.Value {
			needed = append(needed, kv)
		}
	}

	if len(needed) == 0 {
		return &model.PlannedAction{
			FindingID:  finding.ID,
			ModuleID:   meta.ID,
			Applicable: false,
			SkipReason: "all required sysctl values already match the hardened profile",
		}, nil
	}

	steps := make([]string, len(needed))
	for i, kv := range needed {
		steps[i] = fmt.Sprintf("set %s = %s", kv.Key, kv.Value)
	}

	return &model.PlannedAction{
		FindingID:   finding.ID,
		ModuleID:    meta.ID,
		Title:       "Harden kernel sysctl parameters",
		Description: fmt.Sprintf("Write %s with %d parameter(s) and activate via sysctl --system", ConfPath, len(needed)),
		Steps:       steps,
		Metadata: map[string]string{
			"target_file":  ConfPath,
			"change_count": fmt.Sprintf("%d", len(needed)),
		},
		Risk:        model.RiskMedium,
		Impact:      "Applies network and kernel hardening parameters. Does not touch ip_forward — safe in container hosts.",
		CanRollback: true,
		Applicable:  true,
		Tags:        []string{"network-safe"},
	}, nil
}

// Apply writes the sysctl drop-in file and runs sysctl --system to activate it.
func (m *Module) Apply(ctx context.Context, action *model.PlannedAction, exec executor.Executor) (*model.AppliedAction, error) {
	content := buildConfContent()

	if err := exec.WriteFile(ctx, ConfPath, []byte(content), 0644); err != nil {
		return nil, fmt.Errorf("writing %s: %w", ConfPath, err)
	}

	if _, err := exec.Run(ctx, "sysctl", "--system"); err != nil {
		return nil, fmt.Errorf("activating sysctl settings: %w", err)
	}

	return &model.AppliedAction{
		PlannedAction: *action,
		AppliedAt:     time.Now(),
		Status:        model.ActionApplied,
	}, nil
}

// Validate re-reads each sysctl key and confirms the live value matches.
func (m *Module) Validate(ctx context.Context, _ *model.PlannedAction, inspect executor.Inspector) error {
	for _, kv := range desiredValues {
		current, err := inspect.GetSysctl(ctx, kv.Key)
		if err != nil {
			return fmt.Errorf("reading sysctl %s for validation: %w", kv.Key, err)
		}
		if strings.TrimSpace(current) != kv.Value {
			return fmt.Errorf("validation failed: %s = %q, want %q", kv.Key, current, kv.Value)
		}
	}
	return nil
}

// Rollback restores the sysctl.d file from backup and re-activates the original values.
func (m *Module) Rollback(ctx context.Context, entry *model.RollbackEntry, exec executor.Executor) error {
	if entry.Kind != model.RollbackFile {
		return fmt.Errorf("kernel-sysctl rollback: unexpected kind %q", entry.Kind)
	}

	backup, err := exec.ReadFile(ctx, entry.BackupPath)
	if err != nil {
		return fmt.Errorf("reading backup at %s: %w", entry.BackupPath, err)
	}

	if err := exec.WriteFile(ctx, entry.Path, backup, entry.OrigMode); err != nil {
		return fmt.Errorf("restoring %s: %w", entry.Path, err)
	}

	if _, err := exec.Run(ctx, "sysctl", "--system"); err != nil {
		return fmt.Errorf("re-activating sysctl after rollback: %w", err)
	}

	return nil
}

// buildConfContent renders the full file content for 99-hardener.conf.
func buildConfContent() string {
	var sb strings.Builder
	sb.WriteString("# Managed by hardener — do not edit manually.\n")
	for _, kv := range desiredValues {
		fmt.Fprintf(&sb, "%s = %s\n", kv.Key, kv.Value)
	}
	return sb.String()
}
