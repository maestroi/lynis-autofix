package logrotate

import (
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/maestroi/hardener/internal/executor"
	"github.com/maestroi/hardener/internal/model"
	"github.com/maestroi/hardener/internal/modules"
)

// ConfigPath is the main logrotate configuration file.
const ConfigPath = "/etc/logrotate.conf"

// activeCompressRe matches an uncommented compress directive on its own line.
var activeCompressRe = regexp.MustCompile(`(?m)^\s*compress\s*$`)

// Module remediates LOGG-2154 by enabling log compression in logrotate.conf.
type Module struct{}

func New() *Module { return &Module{} }

func (m *Module) Metadata() modules.ModuleMetadata {
	return modules.ModuleMetadata{
		ID:               "logging-logrotate-compress",
		Name:             "Enable Logrotate Compression",
		Description:      "Enables log compression in /etc/logrotate.conf to reduce disk usage",
		Category:         "Logging",
		DefaultRisk:      model.RiskLow,
		SupportedDistros: []string{"ubuntu"},
		Tags:             []string{"network-safe", "docker-safe"},
		CanRollback:      true,
		RequiresReboot:   false,
	}
}

func (m *Module) SupportedFindings() []string {
	return []string{"LOGG-2154"}
}

func (m *Module) Plan(ctx context.Context, finding *model.Finding, _ *model.Profile, inspect executor.Inspector) (*model.PlannedAction, error) {
	meta := m.Metadata()

	content, err := inspect.ReadFile(ctx, ConfigPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &model.PlannedAction{
				FindingID:  finding.ID,
				ModuleID:   meta.ID,
				Applicable: false,
				SkipReason: fmt.Sprintf("%s not found — logrotate may not be installed", ConfigPath),
			}, nil
		}
		return nil, fmt.Errorf("reading %s: %w", ConfigPath, err)
	}

	if activeCompressRe.MatchString(string(content)) {
		return &model.PlannedAction{
			FindingID:  finding.ID,
			ModuleID:   meta.ID,
			Applicable: false,
			SkipReason: fmt.Sprintf("%s: compress is already enabled", ConfigPath),
		}, nil
	}

	return &model.PlannedAction{
		FindingID:   finding.ID,
		ModuleID:    meta.ID,
		Title:       "Enable logrotate compression",
		Description: fmt.Sprintf("Add 'compress' directive to global options in %s", ConfigPath),
		Steps:       []string{fmt.Sprintf("Uncomment or add 'compress' in %s global options", ConfigPath)},
		Metadata:    map[string]string{"target_file": ConfigPath},
		Risk:        model.RiskLow,
		CanRollback: true,
		Applicable:  true,
		Tags:        []string{"network-safe", "docker-safe"},
	}, nil
}

func (m *Module) Apply(ctx context.Context, action *model.PlannedAction, exec executor.Executor) (*model.AppliedAction, error) {
	content, err := exec.ReadFile(ctx, ConfigPath)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", ConfigPath, err)
	}

	updated := enableCompress(string(content))

	if err := exec.WriteFile(ctx, ConfigPath, []byte(updated), 0644); err != nil {
		return nil, fmt.Errorf("writing %s: %w", ConfigPath, err)
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
		path = ConfigPath
	}
	content, err := inspect.ReadFile(ctx, path)
	if err != nil {
		return fmt.Errorf("reading %s for validation: %w", path, err)
	}
	if !activeCompressRe.MatchString(string(content)) {
		return fmt.Errorf("%s: compress directive is not active after apply", path)
	}
	return nil
}

func (m *Module) Rollback(ctx context.Context, entry *model.RollbackEntry, exec executor.Executor) error {
	if entry.Kind != model.RollbackFile {
		return fmt.Errorf("logging-logrotate-compress rollback: unexpected kind %q", entry.Kind)
	}
	backup, err := exec.ReadFile(ctx, entry.BackupPath)
	if err != nil {
		return fmt.Errorf("reading backup %s: %w", entry.BackupPath, err)
	}
	return exec.WriteFile(ctx, entry.Path, backup, entry.OrigMode)
}

// enableCompress uncomments "#compress" if present, otherwise appends compress after the
// last directive that is not an include or comment in the global options block.
func enableCompress(config string) string {
	// First try to uncomment #compress
	uncommentRe := regexp.MustCompile(`(?m)^(\s*)#\s*(compress)\s*$`)
	if uncommentRe.MatchString(config) {
		return uncommentRe.ReplaceAllString(config, "$1$2")
	}

	// Append before the first include directive if present, otherwise at end.
	includeRe := regexp.MustCompile(`(?m)^include\s+`)
	loc := includeRe.FindStringIndex(config)
	if loc != nil {
		return config[:loc[0]] + "compress\n\n" + config[loc[0]:]
	}

	// Fallback: append at end, ensuring trailing newline.
	if !strings.HasSuffix(config, "\n") {
		config += "\n"
	}
	return config + "compress\n"
}
