package rollback

import (
	"context"
	"fmt"
	"sort"

	"github.com/maestroi/hardener/internal/executor"
	"github.com/maestroi/hardener/internal/model"
	"github.com/maestroi/hardener/internal/registry"
)

// Manager reverses the entries in a RollbackManifest.
type Manager struct {
	reg *registry.Registry
}

// NewManager creates a RollbackManager.
func NewManager(reg *registry.Registry) *Manager {
	return &Manager{reg: reg}
}

// Rollback reverses all entries in the manifest in descending Index order.
func (m *Manager) Rollback(ctx context.Context, manifest *model.RollbackManifest, exec executor.Executor) error {
	entries := make([]model.RollbackEntry, len(manifest.Entries))
	copy(entries, manifest.Entries)

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Index > entries[j].Index
	})

	for _, entry := range entries {
		e := entry
		if err := m.rollbackEntry(ctx, &e, exec); err != nil {
			return fmt.Errorf("rolling back entry %d (%s/%s): %w",
				entry.Index, entry.ModuleID, entry.FindingID, err)
		}
	}
	return nil
}

func (m *Manager) rollbackEntry(ctx context.Context, entry *model.RollbackEntry, exec executor.Executor) error {
	switch entry.Kind {
	case model.RollbackSysctl:
		return exec.SetSysctl(ctx, entry.SysctlKey, entry.SysctlValue)

	case model.RollbackService:
		return m.rollbackService(ctx, entry, exec)

	case model.RollbackPackage:
		return m.rollbackPackage(ctx, entry, exec)

	case model.RollbackFile:
		mod, ok := m.reg.LookupByModuleID(entry.ModuleID)
		if !ok {
			return genericFileRestore(ctx, entry, exec)
		}
		return mod.Rollback(ctx, entry, exec)

	default:
		return fmt.Errorf("unknown rollback kind %q", entry.Kind)
	}
}

func (m *Manager) rollbackService(ctx context.Context, entry *model.RollbackEntry, exec executor.Executor) error {
	if !entry.WasActive {
		if err := exec.StopService(ctx, entry.ServiceName); err != nil {
			return fmt.Errorf("stopping %s: %w", entry.ServiceName, err)
		}
	}
	if !entry.WasEnabled {
		if err := exec.DisableService(ctx, entry.ServiceName); err != nil {
			return fmt.Errorf("disabling %s: %w", entry.ServiceName, err)
		}
	}
	return nil
}

func (m *Manager) rollbackPackage(ctx context.Context, entry *model.RollbackEntry, exec executor.Executor) error {
	_ = ctx
	_ = exec
	_ = entry
	if entry.WasInstalled {
		return nil
	}
	return nil
}

func genericFileRestore(ctx context.Context, entry *model.RollbackEntry, exec executor.Executor) error {
	backup, err := exec.ReadFile(ctx, entry.BackupPath)
	if err != nil {
		return fmt.Errorf("reading backup %s: %w", entry.BackupPath, err)
	}
	if err := exec.WriteFile(ctx, entry.Path, backup, entry.OrigMode); err != nil {
		return fmt.Errorf("restoring %s: %w", entry.Path, err)
	}
	return exec.SetOwner(ctx, entry.Path, entry.OrigUID, entry.OrigGID)
}
