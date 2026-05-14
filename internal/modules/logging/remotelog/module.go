package remotelog

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
	ConfPath    = "/etc/rsyslog.d/99-hardener-remote.conf"
	serviceName = "rsyslog"
)

type Module struct{}

func New() *Module { return &Module{} }

func (m *Module) Metadata() modules.ModuleMetadata {
	return modules.ModuleMetadata{
		ID:               "logging-remotelog",
		Name:             "Configure Remote Syslog",
		Description:      "Forwards syslog events to a remote server via rsyslog TCP transport",
		Category:         "Logging",
		DefaultRisk:      model.RiskMedium,
		SupportedDistros: []string{"ubuntu"},
		Tags:             []string{"network-safe"},
		CanRollback:      true,
		RequiresReboot:   false,
	}
}

func (m *Module) SupportedFindings() []string {
	return []string{"LOGG-2190"}
}

func (m *Module) Plan(ctx context.Context, finding *model.Finding, profile *model.Profile, inspect executor.Inspector) (*model.PlannedAction, error) {
	meta := m.Metadata()

	if profile.RemoteSyslogServer == "" {
		return &model.PlannedAction{
			FindingID:  finding.ID,
			ModuleID:   meta.ID,
			Applicable: false,
			SkipReason: "blocked by policy/config: set remote_syslog_server in profile to enable LOGG-2190 remediation (e.g. \"10.0.0.1:514\")",
		}, nil
	}

	content, err := inspect.ReadFile(ctx, ConfPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("logging-remotelog: reading %s: %w", ConfPath, err)
	}

	if err == nil && strings.Contains(string(content), profile.RemoteSyslogServer) {
		return &model.PlannedAction{
			FindingID:  finding.ID,
			ModuleID:   meta.ID,
			Applicable: false,
			SkipReason: fmt.Sprintf("already compliant: %s already forwards to %s", ConfPath, profile.RemoteSyslogServer),
		}, nil
	}

	return &model.PlannedAction{
		FindingID:   finding.ID,
		ModuleID:    meta.ID,
		Title:       "Configure remote syslog forwarding",
		Description: fmt.Sprintf("Forward all syslog events to %s via TCP", profile.RemoteSyslogServer),
		Steps: []string{
			fmt.Sprintf("write %s with @@%s target", ConfPath, profile.RemoteSyslogServer),
			fmt.Sprintf("systemctl restart %s", serviceName),
		},
		Metadata:    map[string]string{"server": profile.RemoteSyslogServer, "target_file": ConfPath},
		Risk:        model.RiskMedium,
		CanRollback: true,
		Applicable:  true,
		Tags:        []string{"network-safe"},
	}, nil
}

func (m *Module) Apply(ctx context.Context, action *model.PlannedAction, exec executor.Executor) (*model.AppliedAction, error) {
	server := action.Metadata["server"]
	content := fmt.Sprintf("# Managed by hardener — do not edit manually.\n*.* @@%s\n", server)

	if err := exec.WriteFile(ctx, ConfPath, []byte(content), 0644); err != nil {
		return nil, fmt.Errorf("logging-remotelog: writing %s: %w", ConfPath, err)
	}

	if err := exec.RestartService(ctx, serviceName); err != nil {
		return nil, fmt.Errorf("logging-remotelog: restarting %s: %w", serviceName, err)
	}

	return &model.AppliedAction{
		PlannedAction: *action,
		AppliedAt:     time.Now(),
		Status:        model.ActionApplied,
	}, nil
}

func (m *Module) Validate(ctx context.Context, action *model.PlannedAction, inspect executor.Inspector) error {
	server := action.Metadata["server"]
	content, err := inspect.ReadFile(ctx, ConfPath)
	if err != nil {
		return fmt.Errorf("logging-remotelog: reading %s: %w", ConfPath, err)
	}
	if !strings.Contains(string(content), server) {
		return fmt.Errorf("logging-remotelog: remote server %s not found in %s", server, ConfPath)
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
			return fmt.Errorf("logging-remotelog: reading backup %s: %w", entry.BackupPath, err)
		}
		if err := exec.WriteFile(ctx, entry.Path, backup, entry.OrigMode); err != nil {
			return fmt.Errorf("logging-remotelog: restoring %s: %w", entry.Path, err)
		}
		return exec.RestartService(ctx, serviceName)
	default:
		return fmt.Errorf("logging-remotelog rollback: unexpected kind %q", entry.Kind)
	}
}
