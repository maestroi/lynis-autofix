package backup

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/maestroi/hardener/internal/model"
)

// Store handles pre-mutation snapshots of system state.
// All backups for a run are stored under <backupDir>/<runID>/.
type Store struct {
	backupDir string
}

// NewStore creates a Store rooted at backupDir.
func NewStore(backupDir string) *Store {
	return &Store{backupDir: backupDir}
}

// SnapshotFile copies a file to the backup directory and returns a populated RollbackEntry.
// Must be called before any write to the file.
func (s *Store) SnapshotFile(ctx context.Context, runID, moduleID, findingID string, index int, path string) (model.RollbackEntry, error) {
	_ = ctx
	info, err := os.Lstat(path)
	if err != nil {
		return model.RollbackEntry{}, fmt.Errorf("stat %s: %w", path, err)
	}

	backupPath, err := s.copyFile(runID, path)
	if err != nil {
		return model.RollbackEntry{}, err
	}

	entry := model.RollbackEntry{
		Index:       index,
		CreatedAt:   time.Now().UTC(),
		Description: fmt.Sprintf("Restore %s before %s", path, findingID),
		ModuleID:    moduleID,
		FindingID:   findingID,
		Kind:        model.RollbackFile,
		Path:        path,
		BackupPath:  backupPath,
		OrigMode:    info.Mode(),
	}

	populateOwner(info, &entry)

	return entry, nil
}

// SnapshotSysctl records the current sysctl value before a change.
func (s *Store) SnapshotSysctl(runID, moduleID, findingID string, index int, key, currentValue string) model.RollbackEntry {
	_ = s
	_ = runID
	return model.RollbackEntry{
		Index:       index,
		CreatedAt:   time.Now().UTC(),
		Description: fmt.Sprintf("Restore sysctl %s=%s before %s", key, currentValue, findingID),
		ModuleID:    moduleID,
		FindingID:   findingID,
		Kind:        model.RollbackSysctl,
		SysctlKey:   key,
		SysctlValue: currentValue,
	}
}

// SnapshotService records a service's current enabled/active state before modification.
func (s *Store) SnapshotService(runID, moduleID, findingID string, index int, name string, wasEnabled, wasActive bool) model.RollbackEntry {
	_ = s
	_ = runID
	return model.RollbackEntry{
		Index:       index,
		CreatedAt:   time.Now().UTC(),
		Description: fmt.Sprintf("Restore service %s state before %s", name, findingID),
		ModuleID:    moduleID,
		FindingID:   findingID,
		Kind:        model.RollbackService,
		ServiceName: name,
		WasEnabled:  wasEnabled,
		WasActive:   wasActive,
	}
}

// SnapshotPackage records whether a package was installed before hardener touched it.
func (s *Store) SnapshotPackage(runID, moduleID, findingID string, index int, name string, wasInstalled bool) model.RollbackEntry {
	_ = s
	_ = runID
	return model.RollbackEntry{
		Index:        index,
		CreatedAt:    time.Now().UTC(),
		Description:  fmt.Sprintf("Track package %s installation before %s", name, findingID),
		ModuleID:     moduleID,
		FindingID:    findingID,
		Kind:         model.RollbackPackage,
		PackageName:  name,
		WasInstalled: wasInstalled,
	}
}

func (s *Store) copyFile(runID, srcPath string) (string, error) {
	hash := fmt.Sprintf("%x", sha256.Sum256([]byte(srcPath)))
	destDir := filepath.Join(s.backupDir, runID, hash)
	if err := os.MkdirAll(destDir, 0750); err != nil {
		return "", fmt.Errorf("creating backup dir: %w", err)
	}

	destPath := filepath.Join(destDir, "file")

	src, err := os.Open(srcPath)
	if err != nil {
		return "", fmt.Errorf("opening source %s: %w", srcPath, err)
	}
	defer src.Close()

	dst, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return "", fmt.Errorf("creating backup file: %w", err)
	}
	defer dst.Close()

	if _, err := io.Copy(dst, src); err != nil {
		return "", fmt.Errorf("copying %s to backup: %w", srcPath, err)
	}
	return destPath, nil
}
