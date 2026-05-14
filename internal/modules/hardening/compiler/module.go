package compiler

import (
	"context"
	"fmt"
	"io/fs"
	"strconv"
	"strings"
	"time"

	"github.com/maestroi/hardener/internal/executor"
	"github.com/maestroi/hardener/internal/model"
	"github.com/maestroi/hardener/internal/modules"
)

var compilerTools = []string{"gcc", "cc", "g++", "make"}

type Module struct{}

func New() *Module { return &Module{} }

func (m *Module) Metadata() modules.ModuleMetadata {
	return modules.ModuleMetadata{
		ID:               "hardening-compiler",
		Name:             "Restrict Compiler Access",
		Description:      "Removes world-execute bit from compiler tools (gcc, cc, g++, make) to prevent unprivileged compilation",
		Category:         "Hardening",
		DefaultRisk:      model.RiskMedium,
		SupportedDistros: []string{"ubuntu"},
		Tags:             []string{"network-safe", "docker-safe"},
		CanRollback:      true,
		RequiresReboot:   false,
	}
}

func (m *Module) SupportedFindings() []string {
	return []string{"HRDN-7222"}
}

func (m *Module) Plan(ctx context.Context, finding *model.Finding, _ *model.Profile, inspect executor.Inspector) (*model.PlannedAction, error) {
	meta := m.Metadata()

	var targets []string
	for _, tool := range compilerTools {
		out, err := inspect.RunReadOnly(ctx, "which", tool)
		if err != nil || strings.TrimSpace(out.Stdout) == "" {
			continue
		}
		path := strings.TrimSpace(out.Stdout)

		statOut, err := inspect.RunReadOnly(ctx, "stat", "-c", "%a", path)
		if err != nil {
			continue
		}
		modeStr := strings.TrimSpace(statOut.Stdout)
		mode, err := strconv.ParseUint(modeStr, 8, 32)
		if err != nil {
			continue
		}
		if mode&0001 != 0 {
			targets = append(targets, path)
		}
	}

	if len(targets) == 0 {
		return &model.PlannedAction{
			FindingID:  finding.ID,
			ModuleID:   meta.ID,
			Applicable: false,
			SkipReason: "no compiler tools found with world-execute bit set",
		}, nil
	}

	steps := make([]string, len(targets))
	for i, t := range targets {
		steps[i] = fmt.Sprintf("chmod o-x %s", t)
	}

	return &model.PlannedAction{
		FindingID:   finding.ID,
		ModuleID:    meta.ID,
		Title:       "Remove world-execute from compiler tools",
		Description: fmt.Sprintf("chmod o-x on %d compiler binaries", len(targets)),
		Steps:       steps,
		Metadata:    map[string]string{"targets": strings.Join(targets, ",")},
		Risk:        model.RiskMedium,
		Impact:      "Non-root users will not be able to execute gcc/cc/g++/make directly.",
		CanRollback: true,
		Applicable:  true,
		Tags:        []string{"network-safe", "docker-safe"},
	}, nil
}

func (m *Module) Apply(ctx context.Context, action *model.PlannedAction, exec executor.Executor) (*model.AppliedAction, error) {
	targets := action.Metadata["targets"]
	if targets == "" {
		return &model.AppliedAction{PlannedAction: *action, AppliedAt: time.Now(), Status: model.ActionApplied}, nil
	}

	for _, path := range strings.Split(targets, ",") {
		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}
		statOut, err := exec.RunReadOnly(ctx, "stat", "-c", "%a", path)
		var newMode fs.FileMode = 0750 // safe default if stat fails
		if err == nil {
			modeVal, parseErr := strconv.ParseUint(strings.TrimSpace(statOut.Stdout), 8, 32)
			if parseErr == nil {
				newMode = fs.FileMode(modeVal) &^ 0001
			}
		}
		if err := exec.SetFileMode(ctx, path, newMode); err != nil {
			return nil, fmt.Errorf("hardening-compiler: chmod %s: %w", path, err)
		}
	}

	return &model.AppliedAction{
		PlannedAction: *action,
		AppliedAt:     time.Now(),
		Status:        model.ActionApplied,
	}, nil
}

func (m *Module) Validate(ctx context.Context, action *model.PlannedAction, inspect executor.Inspector) error {
	targets := action.Metadata["targets"]
	if targets == "" {
		return nil
	}
	for _, path := range strings.Split(targets, ",") {
		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}
		out, err := inspect.RunReadOnly(ctx, "stat", "-c", "%a", path)
		if err != nil {
			return fmt.Errorf("hardening-compiler: stat %s: %w", path, err)
		}
		modeStr := strings.TrimSpace(out.Stdout)
		mode, err := strconv.ParseUint(modeStr, 8, 32)
		if err != nil {
			return fmt.Errorf("hardening-compiler: parsing mode %q for %s: %w", modeStr, path, err)
		}
		if mode&0001 != 0 {
			return fmt.Errorf("hardening-compiler: %s still has world-execute bit (mode %s)", path, modeStr)
		}
	}
	return nil
}

func (m *Module) Rollback(ctx context.Context, entry *model.RollbackEntry, exec executor.Executor) error {
	switch entry.Kind {
	case model.RollbackFile:
		if err := exec.SetFileMode(ctx, entry.Path, entry.OrigMode); err != nil {
			return fmt.Errorf("hardening-compiler: restoring mode on %s: %w", entry.Path, err)
		}
		return nil
	default:
		return fmt.Errorf("hardening-compiler rollback: unexpected kind %q", entry.Kind)
	}
}
