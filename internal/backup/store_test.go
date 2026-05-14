package backup_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/maestroi/hardener/internal/backup"
	"github.com/maestroi/hardener/internal/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBackupStore_SnapshotFile(t *testing.T) {
	src := filepath.Join(t.TempDir(), "sshd_config")
	require.NoError(t, os.WriteFile(src, []byte("PermitRootLogin yes\n"), 0644))

	backupDir := t.TempDir()
	store := backup.NewStore(backupDir)

	entry, err := store.SnapshotFile(context.Background(), "run-001", "ssh-hardening", "SSH-7408", 0, src)
	require.NoError(t, err)

	assert.Equal(t, model.RollbackFile, entry.Kind)
	assert.Equal(t, src, entry.Path)
	assert.NotEmpty(t, entry.BackupPath)
	assert.Equal(t, "ssh-hardening", entry.ModuleID)
	assert.Equal(t, "SSH-7408", entry.FindingID)
	assert.NotZero(t, entry.OrigMode)

	data, err := os.ReadFile(entry.BackupPath)
	require.NoError(t, err)
	assert.Equal(t, "PermitRootLogin yes\n", string(data))
}

func TestBackupStore_SnapshotFile_NonExistent_ReturnsError(t *testing.T) {
	store := backup.NewStore(t.TempDir())
	_, err := store.SnapshotFile(context.Background(), "run-001", "m", "F", 0, "/does/not/exist")
	assert.Error(t, err)
}

func TestBackupStore_SnapshotSysctl(t *testing.T) {
	store := backup.NewStore(t.TempDir())
	entry := store.SnapshotSysctl("run-001", "ssh-hardening", "SSH-7408", 0, "net.ipv4.tcp_syncookies", "0")

	assert.Equal(t, model.RollbackSysctl, entry.Kind)
	assert.Equal(t, "net.ipv4.tcp_syncookies", entry.SysctlKey)
	assert.Equal(t, "0", entry.SysctlValue)
}

func TestBackupStore_SnapshotService(t *testing.T) {
	store := backup.NewStore(t.TempDir())
	entry := store.SnapshotService("run-001", "auditd-basic", "LOGG-2190", 0, "auditd", false, false)

	assert.Equal(t, model.RollbackService, entry.Kind)
	assert.Equal(t, "auditd", entry.ServiceName)
	assert.False(t, entry.WasEnabled)
	assert.False(t, entry.WasActive)
}
