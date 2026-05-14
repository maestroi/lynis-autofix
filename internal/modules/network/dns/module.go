package dns

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
	ResolvedConfPath = "/etc/systemd/resolved.conf"
	serviceName      = "systemd-resolved"
)

type Module struct{}

func New() *Module { return &Module{} }

func (m *Module) Metadata() modules.ModuleMetadata {
	return modules.ModuleMetadata{
		ID:               "network-dns",
		Name:             "Enable DNSSEC Validation",
		Description:      "Enables DNSSEC=yes in /etc/systemd/resolved.conf to validate DNS responses",
		Category:         "Network",
		DefaultRisk:      model.RiskMedium,
		SupportedDistros: []string{"ubuntu"},
		Tags:             []string{"network-safe"},
		CanRollback:      true,
		RequiresReboot:   false,
	}
}

func (m *Module) SupportedFindings() []string {
	return []string{"NAME-4028"}
}

func (m *Module) Plan(ctx context.Context, finding *model.Finding, _ *model.Profile, inspect executor.Inspector) (*model.PlannedAction, error) {
	meta := m.Metadata()

	content, err := inspect.ReadFile(ctx, ResolvedConfPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("network-dns: reading %s: %w", ResolvedConfPath, err)
	}

	if err == nil && strings.Contains(string(content), "DNSSEC=yes") {
		return &model.PlannedAction{
			FindingID:  finding.ID,
			ModuleID:   meta.ID,
			Applicable: false,
			SkipReason: fmt.Sprintf("%s already has DNSSEC=yes", ResolvedConfPath),
		}, nil
	}

	return &model.PlannedAction{
		FindingID:   finding.ID,
		ModuleID:    meta.ID,
		Title:       "Enable DNSSEC validation",
		Description: fmt.Sprintf("Set DNSSEC=yes in %s and restart systemd-resolved", ResolvedConfPath),
		Steps: []string{
			fmt.Sprintf("write DNSSEC=yes to %s", ResolvedConfPath),
			fmt.Sprintf("systemctl restart %s", serviceName),
		},
		Metadata:    map[string]string{"target_file": ResolvedConfPath},
		Risk:        model.RiskMedium,
		Impact:      "DNS queries will be validated via DNSSEC. Domains without valid DNSSEC records may fail to resolve.",
		CanRollback: true,
		Applicable:  true,
		Tags:        []string{"network-safe"},
	}, nil
}

func (m *Module) Apply(ctx context.Context, action *model.PlannedAction, exec executor.Executor) (*model.AppliedAction, error) {
	existing, err := exec.ReadFile(ctx, ResolvedConfPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("network-dns: reading %s: %w", ResolvedConfPath, err)
	}

	content := buildResolvedConf(string(existing))
	if err := exec.WriteFile(ctx, ResolvedConfPath, []byte(content), 0644); err != nil {
		return nil, fmt.Errorf("network-dns: writing %s: %w", ResolvedConfPath, err)
	}

	if err := exec.RestartService(ctx, serviceName); err != nil {
		return nil, fmt.Errorf("network-dns: restarting %s: %w", serviceName, err)
	}

	return &model.AppliedAction{
		PlannedAction: *action,
		AppliedAt:     time.Now(),
		Status:        model.ActionApplied,
	}, nil
}

func buildResolvedConf(existing string) string {
	lines := strings.Split(existing, "\n")

	var out []string
	inResolve := false
	dnssecAdded := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "[Resolve]" {
			inResolve = true
			out = append(out, line)
			out = append(out, "DNSSEC=yes")
			dnssecAdded = true
			continue
		}
		if strings.HasPrefix(trimmed, "[") && trimmed != "[Resolve]" {
			inResolve = false
		}
		if inResolve && (strings.HasPrefix(trimmed, "DNSSEC=") || strings.HasPrefix(trimmed, "#DNSSEC=")) {
			continue
		}
		out = append(out, line)
	}

	if !dnssecAdded {
		out = append(out, "[Resolve]", "DNSSEC=yes")
	}

	return strings.Join(out, "\n")
}

func (m *Module) Validate(ctx context.Context, _ *model.PlannedAction, inspect executor.Inspector) error {
	content, err := inspect.ReadFile(ctx, ResolvedConfPath)
	if err != nil {
		return fmt.Errorf("network-dns: reading %s: %w", ResolvedConfPath, err)
	}
	if !strings.Contains(string(content), "DNSSEC=yes") {
		return fmt.Errorf("network-dns: DNSSEC=yes not found in %s", ResolvedConfPath)
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
			return fmt.Errorf("network-dns: reading backup %s: %w", entry.BackupPath, err)
		}
		if err := exec.WriteFile(ctx, entry.Path, backup, entry.OrigMode); err != nil {
			return fmt.Errorf("network-dns: restoring %s: %w", entry.Path, err)
		}
		return exec.RestartService(ctx, serviceName)
	default:
		return fmt.Errorf("network-dns rollback: unexpected kind %q", entry.Kind)
	}
}
