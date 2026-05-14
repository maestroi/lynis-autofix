package banner

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
	IssuePath    = "/etc/issue"
	IssueNetPath = "/etc/issue.net"
)

// legalBanner is the default legal warning text written to banner files.
const legalBanner = `****************************************************************************
AUTHORIZED ACCESS ONLY

This system is restricted to authorized users only. All activity may be
monitored and reported. Unauthorized access is prohibited and may result
in civil and/or criminal liability.

By proceeding, you consent to monitoring.
****************************************************************************
`

// bannerKeyword is the string whose presence indicates a legal banner is already set.
const bannerKeyword = "AUTHORIZED ACCESS ONLY"

// Module remediates BANN-7126 (/etc/issue) and BANN-7130 (/etc/issue.net).
// A single module handles both findings — same logic, different target path.
type Module struct{}

func New() *Module { return &Module{} }

func (m *Module) Metadata() modules.ModuleMetadata {
	return modules.ModuleMetadata{
		ID:               "banner-legal",
		Name:             "Add Legal Login Banner",
		Description:      "Writes a legal access warning to /etc/issue and /etc/issue.net",
		Category:         "Banner",
		DefaultRisk:      model.RiskLow,
		SupportedDistros: []string{"ubuntu"},
		Tags:             []string{"network-safe", "docker-safe"},
		CanRollback:      true,
		RequiresReboot:   false,
	}
}

func (m *Module) SupportedFindings() []string {
	return []string{"BANN-7126", "BANN-7130"}
}

func targetPath(findingID string) string {
	if findingID == "BANN-7130" {
		return IssueNetPath
	}
	return IssuePath
}

func (m *Module) Plan(ctx context.Context, finding *model.Finding, _ *model.Profile, inspect executor.Inspector) (*model.PlannedAction, error) {
	meta := m.Metadata()
	path := targetPath(finding.ID)

	content, err := inspect.ReadFile(ctx, path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}

	if strings.Contains(string(content), bannerKeyword) {
		return &model.PlannedAction{
			FindingID:  finding.ID,
			ModuleID:   meta.ID,
			Applicable: false,
			SkipReason: fmt.Sprintf("%s: legal banner already present", path),
		}, nil
	}

	return &model.PlannedAction{
		FindingID:   finding.ID,
		ModuleID:    meta.ID,
		Title:       fmt.Sprintf("Write legal banner to %s", path),
		Description: fmt.Sprintf("Add authorized-access warning to %s", path),
		Steps:       []string{fmt.Sprintf("Write legal warning text to %s", path)},
		Metadata:    map[string]string{"target_file": path},
		Risk:        model.RiskLow,
		CanRollback: true,
		Applicable:  true,
		Tags:        []string{"network-safe", "docker-safe"},
	}, nil
}

func (m *Module) Apply(ctx context.Context, action *model.PlannedAction, exec executor.Executor) (*model.AppliedAction, error) {
	path := action.Metadata["target_file"]
	if path == "" {
		path = targetPath(action.FindingID)
	}

	if err := exec.WriteFile(ctx, path, []byte(legalBanner), 0644); err != nil {
		return nil, fmt.Errorf("writing banner to %s: %w", path, err)
	}

	return &model.AppliedAction{
		PlannedAction: *action,
		AppliedAt:     time.Now(),
		Status:        model.ActionApplied,
	}, nil
}

func (m *Module) Validate(ctx context.Context, action *model.PlannedAction, inspect executor.Inspector) error {
	path := action.Metadata["target_file"]
	if path == "" {
		path = targetPath(action.FindingID)
	}

	content, err := inspect.ReadFile(ctx, path)
	if err != nil {
		return fmt.Errorf("reading %s for validation: %w", path, err)
	}
	if !strings.Contains(string(content), bannerKeyword) {
		return fmt.Errorf("%s: legal banner keyword not found after apply", path)
	}
	return nil
}

func (m *Module) Rollback(ctx context.Context, entry *model.RollbackEntry, exec executor.Executor) error {
	if entry.Kind != model.RollbackFile {
		return fmt.Errorf("banner-legal rollback: unexpected kind %q", entry.Kind)
	}

	backup, err := exec.ReadFile(ctx, entry.BackupPath)
	if err != nil {
		return fmt.Errorf("reading backup %s: %w", entry.BackupPath, err)
	}

	return exec.WriteFile(ctx, entry.Path, backup, entry.OrigMode)
}
