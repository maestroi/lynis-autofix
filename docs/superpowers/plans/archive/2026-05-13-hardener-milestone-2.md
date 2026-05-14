# Hardener Milestone 2: Executor, State, and Dry-Run Pipeline

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Prerequisite:** Milestone 1 complete — all interfaces defined, model types exist, registry compiles.

**Goal:** Implement the execution infrastructure — DryRunExecutor, StateManager, BackupStore, Planner, SafetyChecker pipeline — and wire a complete `hardener apply --dry-run` pipeline that runs end-to-end with no real system mutations.

**Architecture:** `DryRunExecutor` implements the full `Executor` interface but logs every call and returns safe synthetic results. The apply pipeline is fully wired with planner → safety filter → state management → dry executor. Real mutations (`LocalExecutor`) come in Milestone 3.

**Tech Stack:** Same as Milestone 1. No new dependencies.

---

## File Map

```
internal/executor/dry.go              DryRunExecutor — full Executor, zero side effects
internal/executor/dry_test.go

internal/state/manager.go             StateManager interface
internal/state/store.go               FileStore implementation
internal/state/store_test.go

internal/backup/store.go              BackupStore — snapshots files/sysctl/service state
internal/backup/store_test.go

internal/planner/planner.go           Maps []Finding → []PlannedAction via registry
internal/planner/planner_test.go

internal/safety/checker.go            SafetyChecker interface + pipeline runner
internal/safety/profile_filter.go     Scope-aware protected resource enforcement
internal/safety/profile_filter_test.go
internal/safety/risk_filter.go        Skips actions above MaxRiskLevel
internal/safety/risk_filter_test.go

cmd/apply.go                          Wired apply command (replaces stub)
```

---

### Task 1: DryRunExecutor

**Files:**
- Create: `internal/executor/dry.go`
- Create: `internal/executor/dry_test.go`

The `DryRunExecutor` must implement every method on `Executor`. Read methods return realistic synthetic data. Write methods log the call and no-op. This makes `--dry-run` completely safe for testing on production systems.

- [ ] **Step 1: Write failing DryRunExecutor tests**

```go
// internal/executor/dry_test.go
package executor_test

import (
	"context"
	"io/fs"
	"testing"

	"github.com/maestroi/hardener/internal/executor"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDryRunExecutor_IsDryRun(t *testing.T) {
	e := executor.NewDryRunExecutor()
	assert.True(t, e.IsDryRun())
}

func TestDryRunExecutor_WriteFile_NoSideEffect(t *testing.T) {
	e := executor.NewDryRunExecutor()
	err := e.WriteFile(context.Background(), "/etc/ssh/sshd_config", []byte("content"), 0600)
	require.NoError(t, err)
	// Verify no file was written on the real filesystem
	actions := e.RecordedActions()
	assert.Len(t, actions, 1)
	assert.Equal(t, "WriteFile", actions[0].Method)
	assert.Equal(t, "/etc/ssh/sshd_config", actions[0].Args[0])
}

func TestDryRunExecutor_SetSysctl_NoSideEffect(t *testing.T) {
	e := executor.NewDryRunExecutor()
	err := e.SetSysctl(context.Background(), "net.ipv4.tcp_syncookies", "1")
	require.NoError(t, err)
	actions := e.RecordedActions()
	assert.Len(t, actions, 1)
	assert.Equal(t, "SetSysctl", actions[0].Method)
}

func TestDryRunExecutor_ReadFile_ReturnsSynthetic(t *testing.T) {
	e := executor.NewDryRunExecutor()
	// ReadFile on a non-existent path returns empty content, no error
	content, err := e.ReadFile(context.Background(), "/etc/does-not-exist")
	require.NoError(t, err)
	assert.Empty(t, content) // dry run returns empty, not an error
}

func TestDryRunExecutor_FileExists_ReturnsFalse(t *testing.T) {
	e := executor.NewDryRunExecutor()
	exists, err := e.FileExists(context.Background(), "/any/path")
	require.NoError(t, err)
	assert.False(t, exists) // conservative: assume files don't exist in dry-run
}

func TestDryRunExecutor_ServiceState_ReturnsInactive(t *testing.T) {
	e := executor.NewDryRunExecutor()
	state, err := e.ServiceState(context.Background(), "ssh")
	require.NoError(t, err)
	assert.Equal(t, "ssh", state.Name)
	// Returns a safe default — not assumed active
}

func TestDryRunExecutor_RestartService_Recorded(t *testing.T) {
	e := executor.NewDryRunExecutor()
	err := e.RestartService(context.Background(), "ssh")
	require.NoError(t, err)
	actions := e.RecordedActions()
	assert.Equal(t, "RestartService", actions[0].Method)
	assert.Equal(t, "ssh", actions[0].Args[0])
}

func TestDryRunExecutor_Run_ReturnsEmptyOutput(t *testing.T) {
	e := executor.NewDryRunExecutor()
	out, err := e.Run(context.Background(), "sshd", "-t")
	require.NoError(t, err)
	assert.Equal(t, 0, out.ExitCode)
}

func TestDryRunExecutor_RecordedActions_Order(t *testing.T) {
	e := executor.NewDryRunExecutor()
	_ = e.WriteFile(context.Background(), "/a", nil, 0644)
	_ = e.SetSysctl(context.Background(), "key", "val")
	_ = e.RestartService(context.Background(), "ssh")
	actions := e.RecordedActions()
	assert.Equal(t, []string{"WriteFile", "SetSysctl", "RestartService"},
		[]string{actions[0].Method, actions[1].Method, actions[2].Method})
}
```

- [ ] **Step 2: Run tests — expect compile failure**

```bash
go test ./internal/executor/... 2>&1 | head -10
```

- [ ] **Step 3: Implement `internal/executor/dry.go`**

```go
package executor

import (
	"context"
	"io/fs"
	"sync"
)

// RecordedAction logs a single call made to DryRunExecutor.
type RecordedAction struct {
	Method string
	Args   []string
}

// DryRunExecutor implements Executor with zero side effects.
// All mutating calls are logged to an in-memory action log.
// All read calls return safe synthetic values.
type DryRunExecutor struct {
	mu      sync.Mutex
	actions []RecordedAction
}

// NewDryRunExecutor creates a DryRunExecutor.
func NewDryRunExecutor() *DryRunExecutor {
	return &DryRunExecutor{}
}

func (e *DryRunExecutor) record(method string, args ...string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.actions = append(e.actions, RecordedAction{Method: method, Args: args})
}

// RecordedActions returns all calls made to this executor in order.
func (e *DryRunExecutor) RecordedActions() []RecordedAction {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]RecordedAction, len(e.actions))
	copy(out, e.actions)
	return out
}

// --- Inspector methods (read-only, return synthetic safe values) ---

func (e *DryRunExecutor) ReadFile(_ context.Context, path string) ([]byte, error) {
	return nil, nil // safe empty content
}

func (e *DryRunExecutor) FileExists(_ context.Context, path string) (bool, error) {
	return false, nil // conservative: assume absent
}

func (e *DryRunExecutor) GetSysctl(_ context.Context, key string) (string, error) {
	return "", nil
}

func (e *DryRunExecutor) ServiceState(_ context.Context, name string) (ServiceStatus, error) {
	return ServiceStatus{Name: name, Active: false, Enabled: false}, nil
}

func (e *DryRunExecutor) IsPackageInstalled(_ context.Context, name string) (bool, error) {
	return false, nil
}

func (e *DryRunExecutor) RunReadOnly(_ context.Context, name string, args ...string) (CmdOutput, error) {
	return CmdOutput{ExitCode: 0}, nil
}

// --- Executor mutating methods (logged, no-op) ---

func (e *DryRunExecutor) WriteFile(_ context.Context, path string, content []byte, mode fs.FileMode) error {
	e.record("WriteFile", path)
	return nil
}

func (e *DryRunExecutor) AppendFile(_ context.Context, path string, content []byte) error {
	e.record("AppendFile", path)
	return nil
}

func (e *DryRunExecutor) SetFileMode(_ context.Context, path string, mode fs.FileMode) error {
	e.record("SetFileMode", path)
	return nil
}

func (e *DryRunExecutor) SetOwner(_ context.Context, path string, uid, gid int) error {
	e.record("SetOwner", path)
	return nil
}

func (e *DryRunExecutor) SetSysctl(_ context.Context, key, value string) error {
	e.record("SetSysctl", key, value)
	return nil
}

func (e *DryRunExecutor) EnableService(_ context.Context, name string) error {
	e.record("EnableService", name)
	return nil
}

func (e *DryRunExecutor) DisableService(_ context.Context, name string) error {
	e.record("DisableService", name)
	return nil
}

func (e *DryRunExecutor) StartService(_ context.Context, name string) error {
	e.record("StartService", name)
	return nil
}

func (e *DryRunExecutor) StopService(_ context.Context, name string) error {
	e.record("StopService", name)
	return nil
}

func (e *DryRunExecutor) RestartService(_ context.Context, name string) error {
	e.record("RestartService", name)
	return nil
}

func (e *DryRunExecutor) InstallPackage(_ context.Context, name string) error {
	e.record("InstallPackage", name)
	return nil
}

func (e *DryRunExecutor) Run(_ context.Context, name string, args ...string) (CmdOutput, error) {
	e.record(append([]string{"Run", name}, args...)...)
	return CmdOutput{ExitCode: 0}, nil
}

func (e *DryRunExecutor) IsDryRun() bool { return true }
```

- [ ] **Step 4: Run executor tests**

```bash
go test ./internal/executor/... -v
```

Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/executor/
git commit -m "feat: implement DryRunExecutor with action recording"
```

---

### Task 2: StateManager and FileStore

**Files:**
- Create: `internal/state/manager.go`
- Create: `internal/state/store.go`
- Create: `internal/state/store_test.go`

- [ ] **Step 1: Write failing StateManager tests**

```go
// internal/state/store_test.go
package state_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/maestroi/hardener/internal/model"
	"github.com/maestroi/hardener/internal/state"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTempStore(t *testing.T) *state.FileStore {
	t.Helper()
	dir := t.TempDir()
	s, err := state.NewFileStore(dir)
	require.NoError(t, err)
	return s
}

func TestFileStore_InitRun_CreatesDirectory(t *testing.T) {
	s := newTempStore(t)
	run, err := s.InitRun(context.Background(), "server", false)
	require.NoError(t, err)
	assert.NotEmpty(t, run.ID)
	assert.Equal(t, "server", run.ProfileName)
	assert.Equal(t, model.RunPlanning, run.Status)

	// Verify run directory exists
	runDir := filepath.Join(s.StateDir(), "runs", run.ID)
	_, err = os.Stat(runDir)
	assert.NoError(t, err, "run directory should exist")
}

func TestFileStore_AppendRollbackEntry_WritesToDisk(t *testing.T) {
	s := newTempStore(t)
	run, err := s.InitRun(context.Background(), "server", false)
	require.NoError(t, err)

	entry := model.RollbackEntry{
		Index:       0,
		CreatedAt:   time.Now(),
		Description: "Restore /etc/ssh/sshd_config before SSH-7408",
		ModuleID:    "ssh-hardening",
		FindingID:   "SSH-7408",
		Kind:        model.RollbackFile,
		Path:        "/etc/ssh/sshd_config",
		BackupPath:  "/var/lib/hardener/backups/test/sshd_config",
	}
	err = s.AppendRollbackEntry(context.Background(), run.ID, entry)
	require.NoError(t, err)

	// Verify manifest on disk
	manifest, err := s.LoadRollbackManifest(context.Background(), run.ID)
	require.NoError(t, err)
	require.Len(t, manifest.Entries, 1)
	assert.Equal(t, "SSH-7408", manifest.Entries[0].FindingID)
}

func TestFileStore_RecordApplied_WritesToDisk(t *testing.T) {
	s := newTempStore(t)
	run, err := s.InitRun(context.Background(), "server", false)
	require.NoError(t, err)

	action := &model.AppliedAction{
		PlannedAction: model.PlannedAction{FindingID: "SSH-7408", ModuleID: "ssh-hardening"},
		Status:        model.ActionApplied,
		AppliedAt:     time.Now(),
	}
	err = s.RecordApplied(context.Background(), run.ID, action)
	require.NoError(t, err)

	// Load applied.json
	runDir := filepath.Join(s.StateDir(), "runs", run.ID)
	data, err := os.ReadFile(filepath.Join(runDir, "applied.json"))
	require.NoError(t, err)

	var actions []*model.AppliedAction
	require.NoError(t, json.Unmarshal(data, &actions))
	require.Len(t, actions, 1)
	assert.Equal(t, "SSH-7408", actions[0].FindingID)
}

func TestFileStore_CompleteRun_UpdatesStatus(t *testing.T) {
	s := newTempStore(t)
	run, err := s.InitRun(context.Background(), "server", false)
	require.NoError(t, err)

	err = s.CompleteRun(context.Background(), run.ID, model.RunCompleted)
	require.NoError(t, err)

	loaded, err := s.GetRun(context.Background(), run.ID)
	require.NoError(t, err)
	assert.Equal(t, model.RunCompleted, loaded.Status)
	assert.NotNil(t, loaded.FinishedAt)
}

func TestFileStore_ListRuns_ReturnsAll(t *testing.T) {
	s := newTempStore(t)
	_, err := s.InitRun(context.Background(), "server", false)
	require.NoError(t, err)
	_, err = s.InitRun(context.Background(), "server", true)
	require.NoError(t, err)

	runs, err := s.ListRuns(context.Background())
	require.NoError(t, err)
	assert.Len(t, runs, 2)
}
```

- [ ] **Step 2: Run tests — expect compile failure**

```bash
go test ./internal/state/... 2>&1 | head -10
```

- [ ] **Step 3: Implement `internal/state/manager.go`**

```go
package state

import (
	"context"

	"github.com/maestroi/hardener/internal/model"
)

// StateManager owns the lifecycle of run directories and state persistence.
type StateManager interface {
	InitRun(ctx context.Context, profileName string, dryRun bool) (*model.Run, error)
	SavePlan(ctx context.Context, runID string, actions []*model.PlannedAction) error
	RecordApplied(ctx context.Context, runID string, action *model.AppliedAction) error
	AppendRollbackEntry(ctx context.Context, runID string, entry model.RollbackEntry) error
	CompleteRun(ctx context.Context, runID string, status model.RunStatus) error
	GetRun(ctx context.Context, runID string) (*model.Run, error)
	ListRuns(ctx context.Context) ([]*model.Run, error)
	LoadRollbackManifest(ctx context.Context, runID string) (*model.RollbackManifest, error)
	StateDir() string
}
```

- [ ] **Step 4: Implement `internal/state/store.go`**

```go
package state

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/maestroi/hardener/internal/model"
)

// FileStore implements StateManager using the local filesystem.
// Layout: <stateDir>/runs/<run-id>/{plan,applied,rollback}.json
type FileStore struct {
	dir string
}

// NewFileStore creates a FileStore rooted at dir, creating subdirectories as needed.
func NewFileStore(dir string) (*FileStore, error) {
	for _, sub := range []string{"runs", "backups", "locks"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0750); err != nil {
			return nil, fmt.Errorf("creating state dir %s/%s: %w", dir, sub, err)
		}
	}
	return &FileStore{dir: dir}, nil
}

func (s *FileStore) StateDir() string { return s.dir }

func (s *FileStore) runDir(runID string) string {
	return filepath.Join(s.dir, "runs", runID)
}

func (s *FileStore) InitRun(ctx context.Context, profileName string, dryRun bool) (*model.Run, error) {
	run := &model.Run{
		ID:          fmt.Sprintf("%d", time.Now().UnixNano()),
		StartedAt:   time.Now().UTC(),
		ProfileName: profileName,
		StateDir:    s.dir,
		DryRun:      dryRun,
		Status:      model.RunPlanning,
	}

	runDir := s.runDir(run.ID)
	if err := os.MkdirAll(filepath.Join(runDir, "logs"), 0750); err != nil {
		return nil, fmt.Errorf("creating run dir: %w", err)
	}

	// Write initial run.json
	if err := s.writeJSON(filepath.Join(runDir, "run.json"), run); err != nil {
		return nil, err
	}

	// Append to history.jsonl
	if err := s.appendJSONL(filepath.Join(s.dir, "history.jsonl"), run); err != nil {
		return nil, err
	}

	// Initialize empty rollback manifest
	manifest := &model.RollbackManifest{
		RunID:     run.ID,
		CreatedAt: run.StartedAt,
		Entries:   []model.RollbackEntry{},
	}
	if err := s.writeJSON(filepath.Join(runDir, "rollback.json"), manifest); err != nil {
		return nil, err
	}

	return run, nil
}

func (s *FileStore) SavePlan(ctx context.Context, runID string, actions []*model.PlannedAction) error {
	path := filepath.Join(s.runDir(runID), "plan.json")
	return s.writeJSON(path, actions)
}

func (s *FileStore) RecordApplied(ctx context.Context, runID string, action *model.AppliedAction) error {
	path := filepath.Join(s.runDir(runID), "applied.json")

	// Load existing actions, append, rewrite atomically.
	var actions []*model.AppliedAction
	if data, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(data, &actions)
	}
	actions = append(actions, action)
	return s.writeJSON(path, actions)
}

func (s *FileStore) AppendRollbackEntry(ctx context.Context, runID string, entry model.RollbackEntry) error {
	manifest, err := s.LoadRollbackManifest(ctx, runID)
	if err != nil {
		return err
	}
	manifest.Entries = append(manifest.Entries, entry)
	path := filepath.Join(s.runDir(runID), "rollback.json")
	return s.writeJSON(path, manifest)
}

func (s *FileStore) CompleteRun(ctx context.Context, runID string, status model.RunStatus) error {
	run, err := s.GetRun(ctx, runID)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	run.FinishedAt = &now
	run.Status = status
	return s.writeJSON(filepath.Join(s.runDir(runID), "run.json"), run)
}

func (s *FileStore) GetRun(ctx context.Context, runID string) (*model.Run, error) {
	data, err := os.ReadFile(filepath.Join(s.runDir(runID), "run.json"))
	if err != nil {
		return nil, fmt.Errorf("run %s not found: %w", runID, err)
	}
	var run model.Run
	if err := json.Unmarshal(data, &run); err != nil {
		return nil, fmt.Errorf("parsing run %s: %w", runID, err)
	}
	return &run, nil
}

func (s *FileStore) ListRuns(ctx context.Context) ([]*model.Run, error) {
	entries, err := os.ReadDir(filepath.Join(s.dir, "runs"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var runs []*model.Run
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		run, err := s.GetRun(ctx, e.Name())
		if err != nil {
			continue // skip corrupted run dirs
		}
		runs = append(runs, run)
	}
	sort.Slice(runs, func(i, j int) bool {
		return runs[i].StartedAt.Before(runs[j].StartedAt)
	})
	return runs, nil
}

func (s *FileStore) LoadRollbackManifest(ctx context.Context, runID string) (*model.RollbackManifest, error) {
	data, err := os.ReadFile(filepath.Join(s.runDir(runID), "rollback.json"))
	if err != nil {
		return nil, fmt.Errorf("rollback manifest for run %s: %w", runID, err)
	}
	var manifest model.RollbackManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("parsing rollback manifest: %w", err)
	}
	return &manifest, nil
}

// writeJSON atomically writes v as pretty-printed JSON to path.
func (s *FileStore) writeJSON(path string, v interface{}) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling to %s: %w", path, err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0640); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	return os.Rename(tmp, path)
}

// appendJSONL appends v as a single JSON line to path.
func (s *FileStore) appendJSONL(path string, v interface{}) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = fmt.Fprintf(f, "%s\n", data)
	return err
}
```

- [ ] **Step 5: Run state tests**

```bash
go test ./internal/state/... -v
```

Expected: all PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/state/
git commit -m "feat: implement FileStore state manager with run directory lifecycle"
```

---

### Task 3: BackupStore

**Files:**
- Create: `internal/backup/store.go`
- Create: `internal/backup/store_test.go`

The BackupStore is called by the apply pipeline **before** any mutation. It snapshots files, sysctl values, and service states, and returns a populated `model.RollbackEntry` ready to be appended to the manifest.

- [ ] **Step 1: Write failing BackupStore tests**

```go
// internal/backup/store_test.go
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
	// Create a temp file to simulate the target
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

	// Verify the backup file contains the original content
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
```

- [ ] **Step 2: Run tests — expect compile failure**

```bash
go test ./internal/backup/... 2>&1 | head -10
```

- [ ] **Step 3: Implement `internal/backup/store.go`**

```go
package backup

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
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

	// Extract uid/gid on Linux
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		entry.OrigUID = int(stat.Uid)
		entry.OrigGID = int(stat.Gid)
	}

	return entry, nil
}

// SnapshotSysctl records the current sysctl value before a change.
func (s *Store) SnapshotSysctl(runID, moduleID, findingID string, index int, key, currentValue string) model.RollbackEntry {
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
	// Use a hash of the path as the backup filename to avoid collisions.
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
```

- [ ] **Step 4: Run backup tests**

```bash
go test ./internal/backup/... -v
```

Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/backup/
git commit -m "feat: implement BackupStore for pre-mutation file/sysctl/service snapshots"
```

---

### Task 4: Planner

**Files:**
- Create: `internal/planner/planner.go`
- Create: `internal/planner/planner_test.go`

The Planner queries the registry for each finding, calls `Module.Plan()`, and returns the full list of `PlannedAction`s including not-found stubs.

- [ ] **Step 1: Write failing planner tests**

```go
// internal/planner/planner_test.go
package planner_test

import (
	"context"
	"testing"

	"github.com/maestroi/hardener/internal/executor"
	"github.com/maestroi/hardener/internal/model"
	"github.com/maestroi/hardener/internal/modules"
	"github.com/maestroi/hardener/internal/planner"
	"github.com/maestroi/hardener/internal/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type alwaysApplicableModule struct {
	id string
}

func (m *alwaysApplicableModule) Metadata() modules.ModuleMetadata {
	return modules.ModuleMetadata{ID: m.id, DefaultRisk: model.RiskLow}
}
func (m *alwaysApplicableModule) SupportedFindings() []string { return []string{"SSH-7408"} }
func (m *alwaysApplicableModule) Plan(_ context.Context, f *model.Finding, _ *model.Profile, _ executor.Inspector) (*model.PlannedAction, error) {
	return &model.PlannedAction{
		FindingID:  f.ID,
		ModuleID:   m.id,
		Title:      "Harden SSH",
		Applicable: true,
		Risk:       model.RiskMedium,
		CanRollback: true,
	}, nil
}
func (m *alwaysApplicableModule) Apply(_ context.Context, _ *model.PlannedAction, _ executor.Executor) (*model.AppliedAction, error) {
	return nil, nil
}
func (m *alwaysApplicableModule) Validate(_ context.Context, _ *model.PlannedAction, _ executor.Inspector) error {
	return nil
}
func (m *alwaysApplicableModule) Rollback(_ context.Context, _ *model.RollbackEntry, _ executor.Executor) error {
	return nil
}

func TestPlanner_KnownFinding_ReturnsApplicableAction(t *testing.T) {
	reg := registry.New()
	reg.Register(&alwaysApplicableModule{id: "ssh-hardening"})

	p := planner.New(reg, executor.NewDryRunExecutor())
	profile := &model.Profile{MaxRiskLevel: model.RiskHigh, FailurePolicy: model.FailureRollbackAndStop}
	findings := []*model.Finding{{ID: "SSH-7408", Category: "SSH", Severity: model.SeverityWarning}}

	actions, err := p.Plan(context.Background(), findings, profile)
	require.NoError(t, err)
	require.Len(t, actions, 1)
	assert.True(t, actions[0].Applicable)
	assert.Equal(t, "SSH-7408", actions[0].FindingID)
}

func TestPlanner_UnknownFinding_MarksSkipped(t *testing.T) {
	reg := registry.New() // empty registry
	p := planner.New(reg, executor.NewDryRunExecutor())
	profile := &model.Profile{MaxRiskLevel: model.RiskHigh}
	findings := []*model.Finding{{ID: "UNKN-9999", Category: "UNKN"}}

	actions, err := p.Plan(context.Background(), findings, profile)
	require.NoError(t, err)
	require.Len(t, actions, 1)
	assert.False(t, actions[0].Applicable)
	assert.Contains(t, actions[0].SkipReason, "no module")
}
```

- [ ] **Step 2: Run tests — expect compile failure**

```bash
go test ./internal/planner/... 2>&1 | head -10
```

- [ ] **Step 3: Implement `internal/planner/planner.go`**

```go
package planner

import (
	"context"
	"fmt"

	"github.com/maestroi/hardener/internal/executor"
	"github.com/maestroi/hardener/internal/model"
	"github.com/maestroi/hardener/internal/registry"
)

// Planner maps a slice of Findings to PlannedActions using the module registry.
type Planner struct {
	reg     *registry.Registry
	inspect executor.Inspector
}

// New creates a Planner. inspect is used by Module.Plan() for read-only system state access.
func New(reg *registry.Registry, inspect executor.Inspector) *Planner {
	return &Planner{reg: reg, inspect: inspect}
}

// Plan calls Module.Plan() for each finding. Findings with no registered module
// are returned as skipped actions rather than errors.
func (p *Planner) Plan(ctx context.Context, findings []*model.Finding, profile *model.Profile) ([]*model.PlannedAction, error) {
	actions := make([]*model.PlannedAction, 0, len(findings))

	for _, f := range findings {
		mod, ok := p.reg.Lookup(f.ID)
		if !ok {
			actions = append(actions, &model.PlannedAction{
				FindingID:  f.ID,
				Applicable: false,
				SkipReason: fmt.Sprintf("no module registered for finding %s", f.ID),
			})
			continue
		}

		action, err := mod.Plan(ctx, f, profile, p.inspect)
		if err != nil {
			return nil, fmt.Errorf("planning %s via %s: %w", f.ID, mod.Metadata().ID, err)
		}
		actions = append(actions, action)
	}

	return actions, nil
}
```

- [ ] **Step 4: Run planner tests**

```bash
go test ./internal/planner/... -v
```

Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/planner/
git commit -m "feat: implement Planner — maps findings to PlannedActions via registry"
```

---

### Task 5: Safety Checkers

**Files:**
- Create: `internal/safety/checker.go`
- Create: `internal/safety/profile_filter.go`
- Create: `internal/safety/profile_filter_test.go`
- Create: `internal/safety/risk_filter.go`
- Create: `internal/safety/risk_filter_test.go`

- [ ] **Step 1: Create `internal/safety/checker.go`**

```go
package safety

import (
	"context"

	"github.com/maestroi/hardener/internal/executor"
	"github.com/maestroi/hardener/internal/model"
)

// SafetyResult is the outcome of a single safety check.
type SafetyResult struct {
	Safe    bool
	Reason  string // populated when Safe == false
	Warning string // advisory, shown even when Safe == true
}

// Checker evaluates one safety concern for a planned action.
type Checker interface {
	Check(ctx context.Context, action *model.PlannedAction, exec executor.Executor) (*SafetyResult, error)
}

// RunAll runs all checkers against an action. Returns the first failing result,
// or a passing result with any accumulated warnings.
func RunAll(ctx context.Context, checkers []Checker, action *model.PlannedAction, exec executor.Executor) (*SafetyResult, error) {
	combined := &SafetyResult{Safe: true}
	for _, c := range checkers {
		result, err := c.Check(ctx, action, exec)
		if err != nil {
			return nil, err
		}
		if !result.Safe {
			return result, nil
		}
		if result.Warning != "" {
			if combined.Warning != "" {
				combined.Warning += "; "
			}
			combined.Warning += result.Warning
		}
	}
	return combined, nil
}
```

- [ ] **Step 2: Write failing ProfileFilter tests**

```go
// internal/safety/profile_filter_test.go
package safety_test

import (
	"context"
	"testing"

	"github.com/maestroi/hardener/internal/executor"
	"github.com/maestroi/hardener/internal/model"
	"github.com/maestroi/hardener/internal/safety"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProfileFilter_BlockedModule_NotSafe(t *testing.T) {
	profile := &model.Profile{BlockedModules: []string{"firewall-baseline"}}
	filter := safety.NewProfileFilter(profile)

	action := &model.PlannedAction{ModuleID: "firewall-baseline", Applicable: true}
	result, err := filter.Check(context.Background(), action, executor.NewDryRunExecutor())
	require.NoError(t, err)
	assert.False(t, result.Safe)
	assert.Contains(t, result.Reason, "blocked by profile")
}

func TestProfileFilter_AllowedModule_Safe(t *testing.T) {
	profile := &model.Profile{BlockedModules: []string{"auditd-basic"}}
	filter := safety.NewProfileFilter(profile)

	action := &model.PlannedAction{ModuleID: "ssh-hardening", Applicable: true}
	result, err := filter.Check(context.Background(), action, executor.NewDryRunExecutor())
	require.NoError(t, err)
	assert.True(t, result.Safe)
}

func TestProfileFilter_ProtectedService_NetworkModule_NotSafe(t *testing.T) {
	profile := &model.Profile{ProtectedServices: []string{"docker"}}
	filter := safety.NewProfileFilter(profile)

	// Tags include "service-restart" — the filter blocks service actions for protected services
	action := &model.PlannedAction{
		ModuleID:   "some-module",
		Applicable: true,
		Tags:       []string{"service-restart"},
		Metadata:   map[string]string{"service_name": "docker"},
	}
	result, err := filter.Check(context.Background(), action, executor.NewDryRunExecutor())
	require.NoError(t, err)
	assert.False(t, result.Safe)
	assert.Contains(t, result.Reason, "protected service")
}
```

- [ ] **Step 3: Implement `internal/safety/profile_filter.go`**

```go
package safety

import (
	"context"
	"fmt"

	"github.com/maestroi/hardener/internal/executor"
	"github.com/maestroi/hardener/internal/model"
)

// ProfileFilter enforces scope-aware protected resource rules from a Profile.
// Protected ports → blocks tags: ["firewall", "network", "sysctl"]
// Protected services → blocks tags: ["service-restart", "service-disable"]
// Protected processes → blocks tags: ["process-restart", "process-kill"]
type ProfileFilter struct {
	profile *model.Profile
}

// NewProfileFilter creates a ProfileFilter for the given profile.
func NewProfileFilter(profile *model.Profile) *ProfileFilter {
	return &ProfileFilter{profile: profile}
}

func (f *ProfileFilter) Check(_ context.Context, action *model.PlannedAction, _ executor.Executor) (*SafetyResult, error) {
	// Module allow/block check
	if f.profile.IsModuleBlocked(action.ModuleID) {
		return &SafetyResult{
			Safe:   false,
			Reason: fmt.Sprintf("module %q blocked by profile %q", action.ModuleID, f.profile.Name),
		}, nil
	}
	if !f.profile.IsModuleAllowed(action.ModuleID) {
		return &SafetyResult{
			Safe:   false,
			Reason: fmt.Sprintf("module %q not in allowed_modules list for profile %q", action.ModuleID, f.profile.Name),
		}, nil
	}

	// Scope-aware service protection
	if hasTag(action.Tags, "service-restart", "service-disable") {
		if svc, ok := action.Metadata["service_name"]; ok {
			if f.profile.IsServiceProtected(svc) {
				return &SafetyResult{
					Safe:   false,
					Reason: fmt.Sprintf("protected service %q cannot be restarted/disabled per profile", svc),
				}, nil
			}
		}
	}

	// Scope-aware process protection
	if hasTag(action.Tags, "process-restart", "process-kill") {
		if proc, ok := action.Metadata["process_name"]; ok {
			if f.profile.IsProcessProtected(proc) {
				return &SafetyResult{
					Safe:   false,
					Reason: fmt.Sprintf("protected process %q cannot be affected per profile", proc),
				}, nil
			}
		}
	}

	return &SafetyResult{Safe: true}, nil
}

func hasTag(tags []string, targets ...string) bool {
	for _, t := range tags {
		for _, target := range targets {
			if t == target {
				return true
			}
		}
	}
	return false
}
```

- [ ] **Step 4: Write failing RiskFilter tests**

```go
// internal/safety/risk_filter_test.go
package safety_test

import (
	"context"
	"testing"

	"github.com/maestroi/hardener/internal/executor"
	"github.com/maestroi/hardener/internal/model"
	"github.com/maestroi/hardener/internal/safety"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRiskFilter_AboveThreshold_NotSafe(t *testing.T) {
	profile := &model.Profile{MaxRiskLevel: model.RiskMedium}
	filter := safety.NewRiskFilter(profile)

	action := &model.PlannedAction{Risk: model.RiskHigh}
	result, err := filter.Check(context.Background(), action, executor.NewDryRunExecutor())
	require.NoError(t, err)
	assert.False(t, result.Safe)
	assert.Contains(t, result.Reason, "risk level")
}

func TestRiskFilter_AtThreshold_Safe(t *testing.T) {
	profile := &model.Profile{MaxRiskLevel: model.RiskMedium}
	filter := safety.NewRiskFilter(profile)

	action := &model.PlannedAction{Risk: model.RiskMedium}
	result, err := filter.Check(context.Background(), action, executor.NewDryRunExecutor())
	require.NoError(t, err)
	assert.True(t, result.Safe)
}

func TestRiskFilter_BelowThreshold_Safe(t *testing.T) {
	profile := &model.Profile{MaxRiskLevel: model.RiskHigh}
	filter := safety.NewRiskFilter(profile)

	action := &model.PlannedAction{Risk: model.RiskLow}
	result, err := filter.Check(context.Background(), action, executor.NewDryRunExecutor())
	require.NoError(t, err)
	assert.True(t, result.Safe)
}
```

- [ ] **Step 5: Implement `internal/safety/risk_filter.go`**

```go
package safety

import (
	"context"
	"fmt"

	"github.com/maestroi/hardener/internal/executor"
	"github.com/maestroi/hardener/internal/model"
)

// RiskFilter skips actions whose risk level exceeds the profile's MaxRiskLevel.
type RiskFilter struct {
	profile *model.Profile
}

// NewRiskFilter creates a RiskFilter for the given profile.
func NewRiskFilter(profile *model.Profile) *RiskFilter {
	return &RiskFilter{profile: profile}
}

func (f *RiskFilter) Check(_ context.Context, action *model.PlannedAction, _ executor.Executor) (*SafetyResult, error) {
	if action.Risk > f.profile.MaxRiskLevel {
		return &SafetyResult{
			Safe: false,
			Reason: fmt.Sprintf("risk level %q exceeds profile maximum %q",
				action.Risk.String(), f.profile.MaxRiskLevel.String()),
		}, nil
	}
	return &SafetyResult{Safe: true}, nil
}
```

- [ ] **Step 6: Run safety tests**

```bash
go test ./internal/safety/... -v
```

Expected: all PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/safety/
git commit -m "feat: implement SafetyChecker pipeline, ProfileFilter, and RiskFilter"
```

---

### Task 6: Wire dry-run apply pipeline

**Files:**
- Modify: `cmd/apply.go` (replace stub with real wiring)

- [ ] **Step 1: Replace the apply command stub**

```go
// cmd/apply.go
package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/maestroi/hardener/internal/backup"
	"github.com/maestroi/hardener/internal/config"
	"github.com/maestroi/hardener/internal/executor"
	"github.com/maestroi/hardener/internal/planner"
	"github.com/maestroi/hardener/internal/registry"
	"github.com/maestroi/hardener/internal/reporter"
	"github.com/maestroi/hardener/internal/safety"
	"github.com/maestroi/hardener/internal/scanner/lynis"
	"github.com/maestroi/hardener/internal/state"
)

var (
	applyAudit            bool
	applyDryRun           bool
	applyYes              bool
	applyConfirmDangerous bool
	applyFindings         []string
	applyModules          []string
)

var applyCmd = &cobra.Command{
	Use:   "apply",
	Short: "Apply the remediation plan",
	RunE:  runApply,
}

func init() {
	applyCmd.Flags().BoolVar(&applyAudit, "audit", false, "run fresh Lynis scan before applying")
	applyCmd.Flags().BoolVar(&applyDryRun, "dry-run", false, "no mutations; uses DryRunExecutor")
	applyCmd.Flags().BoolVar(&applyYes, "yes", false, "skip confirmation prompt")
	applyCmd.Flags().BoolVar(&applyConfirmDangerous, "confirm-dangerous", false, "allow Dangerous=true actions")
	applyCmd.Flags().StringSliceVar(&applyFindings, "finding", nil, "apply only specific findings")
	applyCmd.Flags().StringSliceVar(&applyModules, "module", nil, "apply only specific modules")
	rootCmd.AddCommand(applyCmd)
}

func runApply(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	// Load config and profile
	cfg, err := config.LoadConfigFromBytes(nil) // uses defaults; file loading wired in Milestone 3
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}
	if flagStateDir != "" {
		cfg.StateDir = flagStateDir
	}
	if flagProfile != "" {
		cfg.Profile = flagProfile
	}

	profile, err := config.LoadBundledProfile(cfg.Profile)
	if err != nil {
		return fmt.Errorf("loading profile %q: %w", cfg.Profile, err)
	}

	// Choose executor
	var exec executor.Executor
	if applyDryRun {
		exec = executor.NewDryRunExecutor()
		fmt.Fprintln(cmd.OutOrStdout(), "[dry-run] No changes will be made to this system.")
	} else {
		fmt.Fprintln(os.Stderr, "apply without --dry-run requires LocalExecutor (Milestone 3)")
		return fmt.Errorf("real apply not yet implemented — use --dry-run")
	}

	// Choose reporter
	var rep reporter.Reporter
	switch flagOutput {
	case "json":
		rep = reporter.NewJSONReporter(cmd.OutOrStdout())
	default:
		rep = reporter.NewTerminalReporter(cmd.OutOrStdout())
	}

	// Parse findings from Lynis report
	sc := lynis.New(cfg.Lynis.Binary, cfg.Lynis.ExtraFlags)
	findings, err := sc.ParseReport(ctx, cfg.Lynis.ReportPath)
	if err != nil {
		return fmt.Errorf("parsing Lynis report %s: %w", cfg.Lynis.ReportPath, err)
	}

	// Plan
	reg := registry.Default()
	p := planner.New(reg, exec)
	actions, err := p.Plan(ctx, findings, profile)
	if err != nil {
		return fmt.Errorf("planning: %w", err)
	}

	// Run safety checkers
	checkers := []safety.Checker{
		safety.NewProfileFilter(profile),
		safety.NewRiskFilter(profile),
	}
	for _, action := range actions {
		if !action.Applicable {
			continue
		}
		result, err := safety.RunAll(ctx, checkers, action, exec)
		if err != nil {
			return fmt.Errorf("safety check for %s: %w", action.FindingID, err)
		}
		if !result.Safe {
			action.Applicable = false
			action.SkipReason = result.Reason
		}
	}

	// Display plan
	if err := rep.Plan(ctx, actions); err != nil {
		return err
	}

	if applyDryRun {
		fmt.Fprintln(cmd.OutOrStdout(), "\n[dry-run] Plan shown above. No changes applied.")
		return nil
	}

	// State + backup (dry-run exits above, so this is future Milestone 3 territory)
	store, err := state.NewFileStore(cfg.StateDir)
	if err != nil {
		return fmt.Errorf("initializing state store: %w", err)
	}
	_ = backup.NewStore(cfg.StateDir + "/backups")

	run, err := store.InitRun(ctx, cfg.Profile, applyDryRun)
	if err != nil {
		return fmt.Errorf("initializing run: %w", err)
	}

	fmt.Fprintf(cmd.OutOrStdout(), "Run ID: %s\n", run.ID)
	return nil
}
```

- [ ] **Step 2: Build and verify dry-run works end-to-end**

```bash
go build -o hardener .
# Create a minimal test report
mkdir -p /tmp/hardener-test
cat > /tmp/hardener-test/lynis-report.dat << 'EOF'
warning[]=SSH-7408|sshd option PermitRootLogin is not disabled|
suggestion[]=KRNL-6000|One or more sysctl values differ from the scan profile|
hardening_index=62
EOF

./hardener apply --dry-run \
  --state-dir /tmp/hardener-test/state \
  --profile server \
  --config /dev/null 2>&1
```

Expected output: dry-run notice, plan table showing SSH-7408 and KRNL-6000 both skipped (no registered modules yet), "[dry-run] Plan shown above."

- [ ] **Step 3: Run full test suite**

```bash
go test ./... -v 2>&1 | grep -E "^(ok|FAIL|---)"
```

Expected: all packages `ok`.

- [ ] **Step 4: Commit**

```bash
git add cmd/apply.go
git commit -m "feat: wire dry-run apply pipeline — planner, safety, state, reporter"
```

- [ ] **Step 5: Final Milestone 2 commit**

```bash
git add .
git status  # should be clean
git commit --allow-empty -m "chore: milestone 2 complete — executor, state, backup, planner, safety"
```
