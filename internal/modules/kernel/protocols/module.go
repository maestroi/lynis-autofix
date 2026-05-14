package protocols

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
	ConfPath = "/etc/modprobe.d/disable-protocols.conf"

	ConfContent = `# Managed by hardener — do not edit manually.
install dccp /bin/true
install sctp /bin/true
install rds /bin/true
install tipc /bin/true
`
)

type Module struct{}

func New() *Module { return &Module{} }

func (m *Module) Metadata() modules.ModuleMetadata {
	return modules.ModuleMetadata{
		ID:               "kernel-protocols",
		Name:             "Disable Unused Network Protocols",
		Description:      "Blacklists dccp, sctp, rds, and tipc kernel modules to reduce network attack surface",
		Category:         "Kernel",
		DefaultRisk:      model.RiskMedium,
		SupportedDistros: []string{"ubuntu"},
		Tags:             []string{"network-safe"},
		CanRollback:      true,
		RequiresReboot:   true,
	}
}

func (m *Module) SupportedFindings() []string {
	return []string{"NETW-3200"}
}

func (m *Module) Plan(ctx context.Context, finding *model.Finding, _ *model.Profile, inspect executor.Inspector) (*model.PlannedAction, error) {
	meta := m.Metadata()

	content, err := inspect.ReadFile(ctx, ConfPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("kernel-protocols: reading %s: %w", ConfPath, err)
	}

	if err == nil &&
		strings.Contains(string(content), "install dccp") &&
		strings.Contains(string(content), "install sctp") &&
		strings.Contains(string(content), "install rds") &&
		strings.Contains(string(content), "install tipc") {
		return &model.PlannedAction{
			FindingID:  finding.ID,
			ModuleID:   meta.ID,
			Applicable: false,
			SkipReason: fmt.Sprintf("%s already disables dccp/sctp/rds/tipc", ConfPath),
		}, nil
	}

	return &model.PlannedAction{
		FindingID:      finding.ID,
		ModuleID:       meta.ID,
		Title:          "Disable unused network protocols",
		Description:    fmt.Sprintf("Write %s to disable dccp, sctp, rds, tipc modules", ConfPath),
		Steps:          []string{fmt.Sprintf("write %s", ConfPath)},
		Metadata:       map[string]string{"target_file": ConfPath},
		Risk:           model.RiskMedium,
		Impact:         "Prevents loading of dccp/sctp/rds/tipc kernel modules. Takes effect after reboot or modprobe removal.",
		RequiresReboot: true,
		CanRollback:    true,
		Applicable:     true,
		Tags:           []string{"network-safe"},
	}, nil
}

func (m *Module) Apply(ctx context.Context, action *model.PlannedAction, exec executor.Executor) (*model.AppliedAction, error) {
	if err := exec.WriteFile(ctx, ConfPath, []byte(ConfContent), 0644); err != nil {
		return nil, fmt.Errorf("kernel-protocols: writing %s: %w", ConfPath, err)
	}
	return &model.AppliedAction{
		PlannedAction: *action,
		AppliedAt:     time.Now(),
		Status:        model.ActionApplied,
	}, nil
}

func (m *Module) Validate(ctx context.Context, _ *model.PlannedAction, inspect executor.Inspector) error {
	content, err := inspect.ReadFile(ctx, ConfPath)
	if err != nil {
		return fmt.Errorf("kernel-protocols: reading %s: %w", ConfPath, err)
	}
	for _, proto := range []string{"dccp", "sctp", "rds", "tipc"} {
		if !strings.Contains(string(content), fmt.Sprintf("install %s", proto)) {
			return fmt.Errorf("kernel-protocols: %s missing from %s", proto, ConfPath)
		}
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
			return fmt.Errorf("kernel-protocols: reading backup %s: %w", entry.BackupPath, err)
		}
		return exec.WriteFile(ctx, entry.Path, backup, entry.OrigMode)
	default:
		return fmt.Errorf("kernel-protocols rollback: unexpected kind %q", entry.Kind)
	}
}
