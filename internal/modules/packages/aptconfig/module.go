package aptconfig

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
	ConfPath = "/etc/apt/apt.conf.d/99-hardener-apt"

	ConfContent = `// Managed by hardener — do not edit manually.
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
`
)

type Module struct{}

func New() *Module { return &Module{} }

func (m *Module) Metadata() modules.ModuleMetadata {
	return modules.ModuleMetadata{
		ID:               "pkgs-apt-config",
		Name:             "APT Periodic Security Configuration",
		Description:      "Writes APT periodic update and autoclean settings to enforce automatic security patching",
		Category:         "Packages",
		DefaultRisk:      model.RiskLow,
		SupportedDistros: []string{"ubuntu"},
		Tags:             []string{"network-safe", "docker-safe"},
		CanRollback:      true,
		RequiresReboot:   false,
	}
}

func (m *Module) SupportedFindings() []string {
	return []string{"DEB-0280", "DEB-0880"}
}

func (m *Module) Plan(ctx context.Context, finding *model.Finding, _ *model.Profile, inspect executor.Inspector) (*model.PlannedAction, error) {
	meta := m.Metadata()

	content, err := inspect.ReadFile(ctx, ConfPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("reading %s: %w", ConfPath, err)
	}

	if err == nil && strings.Contains(string(content), `APT::Periodic::Update-Package-Lists`) &&
		strings.Contains(string(content), `APT::Periodic::AutocleanInterval`) {
		return &model.PlannedAction{
			FindingID:  finding.ID,
			ModuleID:   meta.ID,
			Applicable: false,
			SkipReason: fmt.Sprintf("%s already contains required APT periodic settings", ConfPath),
		}, nil
	}

	return &model.PlannedAction{
		FindingID:   finding.ID,
		ModuleID:    meta.ID,
		Title:       "Write APT periodic security config",
		Description: fmt.Sprintf("Create %s with automatic update and autoclean settings", ConfPath),
		Steps:       []string{fmt.Sprintf("write %s", ConfPath)},
		Metadata:    map[string]string{"target_file": ConfPath},
		Risk:        model.RiskLow,
		CanRollback: true,
		Applicable:  true,
		Tags:        []string{"network-safe", "docker-safe"},
	}, nil
}

func (m *Module) Apply(ctx context.Context, action *model.PlannedAction, exec executor.Executor) (*model.AppliedAction, error) {
	if err := exec.WriteFile(ctx, ConfPath, []byte(ConfContent), 0644); err != nil {
		return nil, fmt.Errorf("pkgs-apt-config: writing %s: %w", ConfPath, err)
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
		return fmt.Errorf("pkgs-apt-config: reading %s: %w", ConfPath, err)
	}
	if !strings.Contains(string(content), `APT::Periodic::Update-Package-Lists`) {
		return fmt.Errorf("pkgs-apt-config: APT::Periodic::Update-Package-Lists missing from %s", ConfPath)
	}
	if !strings.Contains(string(content), `APT::Periodic::AutocleanInterval`) {
		return fmt.Errorf("pkgs-apt-config: APT::Periodic::AutocleanInterval missing from %s", ConfPath)
	}
	return nil
}

func (m *Module) Rollback(ctx context.Context, entry *model.RollbackEntry, exec executor.Executor) error {
	switch entry.Kind {
	case model.RollbackFile:
		if entry.BackupPath == "" {
			return nil // file didn't exist before; nothing to restore
		}
		backup, err := exec.ReadFile(ctx, entry.BackupPath)
		if err != nil {
			return fmt.Errorf("pkgs-apt-config: reading backup %s: %w", entry.BackupPath, err)
		}
		return exec.WriteFile(ctx, entry.Path, backup, entry.OrigMode)
	default:
		return fmt.Errorf("pkgs-apt-config rollback: unexpected kind %q", entry.Kind)
	}
}
