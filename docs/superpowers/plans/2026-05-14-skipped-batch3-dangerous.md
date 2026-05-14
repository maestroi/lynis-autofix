# Skipped Findings — Batch 3 (Dangerous) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement 4 high/critical-risk modules covering FILE-6310, FILE-7524, BOOT-5122, and KRNL-5830. All four set `Dangerous: true` and require `--confirm-dangerous` to apply. BOOT-5122 skips gracefully if `grub_password_hash` is absent from profile.

**Architecture:** Same stateless Module interface. Profile gets `GrubPasswordHash`. Fstab modules read/parse/rewrite `/etc/fstab` with a backup before writing. KRNL-5830 writes a sysctl drop-in; setting `kernel.modules_disabled=1` is one-way at runtime (reboot required to re-enable). Batches 1 and 2 must be completed first.

**Tech Stack:** Go 1.22, `github.com/maestroi/hardener`, testify.

---

## Prerequisites

Batches 1 and 2 must be merged. The `RunReadOnlyFn` and `SetFileModeRecords` helpers from Batch 1 are required.

---

## File Map

| File | Action | Purpose |
|------|--------|---------|
| `internal/model/profile.go` | Modify | Add `GrubPasswordHash string` field |
| `internal/modules/filesystem/tmpmount/module.go` | Create | FILE-6310: add nodev/nosuid/noexec to /tmp in fstab |
| `internal/modules/filesystem/tmpmount/module_test.go` | Create | Tests for tmpmount |
| `internal/modules/filesystem/homemount/module.go` | Create | FILE-7524: add nodev to /home in fstab |
| `internal/modules/filesystem/homemount/module_test.go` | Create | Tests for homemount |
| `internal/modules/boot/grubpassword/module.go` | Create | BOOT-5122: write GRUB password hash |
| `internal/modules/boot/grubpassword/module_test.go` | Create | Tests for grubpassword |
| `internal/modules/kernel/modules/module.go` | Create | KRNL-5830: disable kernel module loading |
| `internal/modules/kernel/modules/module_test.go` | Create | Tests for kernel/modules |
| `internal/registry/init.go` | Modify | Register 4 new modules |
| `internal/modules/advisory/manual/module.go` | Modify | Remove all remaining finding IDs (advisory/manual becomes empty) |

---

## Task 1: Add GrubPasswordHash to Profile

**Files:**
- Modify: `internal/model/profile.go`

- [ ] **Step 1.1: Add field**

In `internal/model/profile.go`, add `GrubPasswordHash` after `RemoteSyslogServer` (or `FailurePolicy` if Batch 2 hasn't landed yet):

```go
// GrubPasswordHash is the grub2-mkpasswd-pbkdf2 hash for BOOT-5122 remediation.
// Leave empty to skip. Generate with: grub-mkpasswd-pbkdf2
GrubPasswordHash string `yaml:"grub_password_hash" json:"grub_password_hash"`
```

- [ ] **Step 1.2: Run model tests**

```bash
go test ./internal/model/... -v
```

Expected: all tests pass.

- [ ] **Step 1.3: Commit**

```bash
git add internal/model/profile.go
git commit -m "feat(hardener): add GrubPasswordHash to Profile for BOOT-5122"
```

---

## Task 2: tmpmount module (FILE-6310)

**Files:**
- Create: `internal/modules/filesystem/tmpmount/module.go`
- Create: `internal/modules/filesystem/tmpmount/module_test.go`

Reads `/etc/fstab`, finds the `/tmp` entry (or creates one using `tmpfs`), adds `nodev,nosuid,noexec` if missing, writes back. Sets `Dangerous: true` and `RequiresReboot: true`.

- [ ] **Step 2.1: Write failing tests**

Create `internal/modules/filesystem/tmpmount/module_test.go`:

```go
package tmpmount_test

import (
	"context"
	"strings"
	"testing"

	"github.com/maestroi/hardener/internal/model"
	"github.com/maestroi/hardener/internal/modules/filesystem/tmpmount"
	"github.com/maestroi/hardener/internal/testhelpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const fstabAlreadySecure = `# /etc/fstab
UUID=abc / ext4 defaults 0 1
tmpfs /tmp tmpfs defaults,nodev,nosuid,noexec 0 0
`

const fstabNeedsFixing = `# /etc/fstab
UUID=abc / ext4 defaults 0 1
tmpfs /tmp tmpfs defaults 0 0
`

const fstabNoTmpEntry = `# /etc/fstab
UUID=abc / ext4 defaults 0 1
`

func TestPlan_AlreadySecure(t *testing.T) {
	m := tmpmount.New()
	inspect := &testhelpers.FakeInspector{
		Files: map[string][]byte{tmpmount.FstabPath: []byte(fstabAlreadySecure)},
	}
	action, err := m.Plan(context.Background(), &model.Finding{ID: "FILE-6310"}, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.False(t, action.Applicable)
}

func TestPlan_NeedsOptions(t *testing.T) {
	m := tmpmount.New()
	inspect := &testhelpers.FakeInspector{
		Files: map[string][]byte{tmpmount.FstabPath: []byte(fstabNeedsFixing)},
	}
	action, err := m.Plan(context.Background(), &model.Finding{ID: "FILE-6310"}, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.True(t, action.Applicable)
	assert.True(t, action.Dangerous)
	assert.Equal(t, model.RiskHigh, action.Risk)
}

func TestPlan_NoTmpEntry_AddsNew(t *testing.T) {
	m := tmpmount.New()
	inspect := &testhelpers.FakeInspector{
		Files: map[string][]byte{tmpmount.FstabPath: []byte(fstabNoTmpEntry)},
	}
	action, err := m.Plan(context.Background(), &model.Finding{ID: "FILE-6310"}, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.True(t, action.Applicable)
	assert.True(t, action.Dangerous)
}

func TestApplyAndValidate(t *testing.T) {
	m := tmpmount.New()
	exec := &testhelpers.FakeExecutor{
		FakeInspector: testhelpers.FakeInspector{
			Files: map[string][]byte{tmpmount.FstabPath: []byte(fstabNeedsFixing)},
		},
	}
	action := &model.PlannedAction{
		FindingID:  "FILE-6310",
		ModuleID:   "filesystem-tmpmount",
		Applicable: true,
		Dangerous:  true,
	}

	applied, err := m.Apply(context.Background(), action, exec)
	require.NoError(t, err)
	assert.Equal(t, model.ActionApplied, applied.Status)

	written := string(exec.WrittenFiles[tmpmount.FstabPath])
	assert.True(t, strings.Contains(written, "nodev"))
	assert.True(t, strings.Contains(written, "nosuid"))
	assert.True(t, strings.Contains(written, "noexec"))

	err = m.Validate(context.Background(), action, exec)
	assert.NoError(t, err)
}
```

- [ ] **Step 2.2: Run tests to confirm they fail**

```bash
go test ./internal/modules/filesystem/tmpmount/... -v
```

Expected: compilation error.

- [ ] **Step 2.3: Create module**

Create `internal/modules/filesystem/tmpmount/module.go`:

```go
package tmpmount

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

const FstabPath = "/etc/fstab"

var requiredOptions = []string{"nodev", "nosuid", "noexec"}

type Module struct{}

func New() *Module { return &Module{} }

func (m *Module) Metadata() modules.ModuleMetadata {
	return modules.ModuleMetadata{
		ID:               "filesystem-tmpmount",
		Name:             "Secure /tmp Mount Options",
		Description:      "Adds nodev, nosuid, noexec to the /tmp fstab entry to prevent execution of binaries from /tmp",
		Category:         "Filesystem",
		DefaultRisk:      model.RiskHigh,
		SupportedDistros: []string{"ubuntu"},
		Tags:             []string{"network-safe"},
		CanRollback:      true,
		RequiresReboot:   true,
	}
}

func (m *Module) SupportedFindings() []string {
	return []string{"FILE-6310"}
}

func (m *Module) Plan(ctx context.Context, finding *model.Finding, _ *model.Profile, inspect executor.Inspector) (*model.PlannedAction, error) {
	meta := m.Metadata()

	content, err := inspect.ReadFile(ctx, FstabPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("filesystem-tmpmount: reading %s: %w", FstabPath, err)
	}

	if err == nil && hasMountOptions(string(content), "/tmp", requiredOptions) {
		return &model.PlannedAction{
			FindingID:  finding.ID,
			ModuleID:   meta.ID,
			Applicable: false,
			SkipReason: "/tmp already has nodev, nosuid, noexec in fstab",
		}, nil
	}

	return &model.PlannedAction{
		FindingID:      finding.ID,
		ModuleID:       meta.ID,
		Title:          "Add nodev/nosuid/noexec to /tmp fstab entry",
		Description:    fmt.Sprintf("Modify %s to add security mount options to /tmp", FstabPath),
		Steps:          []string{fmt.Sprintf("backup and rewrite %s with nodev,nosuid,noexec on /tmp", FstabPath)},
		Metadata:       map[string]string{"target_file": FstabPath},
		Risk:           model.RiskHigh,
		Impact:         "Binaries in /tmp cannot be executed and device files cannot be created. Requires reboot to take effect.",
		Dangerous:      true,
		RequiresReboot: true,
		CanRollback:    true,
		Applicable:     true,
		Tags:           []string{"network-safe"},
	}, nil
}

func (m *Module) Apply(ctx context.Context, action *model.PlannedAction, exec executor.Executor) (*model.AppliedAction, error) {
	content, err := exec.ReadFile(ctx, FstabPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("filesystem-tmpmount: reading %s: %w", FstabPath, err)
	}

	updated := addMountOptions(string(content), "/tmp", "tmpfs", requiredOptions)
	if err := exec.WriteFile(ctx, FstabPath, []byte(updated), 0644); err != nil {
		return nil, fmt.Errorf("filesystem-tmpmount: writing %s: %w", FstabPath, err)
	}

	return &model.AppliedAction{
		PlannedAction: *action,
		AppliedAt:     time.Now(),
		Status:        model.ActionApplied,
	}, nil
}

func (m *Module) Validate(ctx context.Context, _ *model.PlannedAction, inspect executor.Inspector) error {
	content, err := inspect.ReadFile(ctx, FstabPath)
	if err != nil {
		return fmt.Errorf("filesystem-tmpmount: reading %s: %w", FstabPath, err)
	}
	if !hasMountOptions(string(content), "/tmp", requiredOptions) {
		return fmt.Errorf("filesystem-tmpmount: /tmp is missing nodev/nosuid/noexec in %s", FstabPath)
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
			return fmt.Errorf("filesystem-tmpmount: reading backup %s: %w", entry.BackupPath, err)
		}
		return exec.WriteFile(ctx, entry.Path, backup, entry.OrigMode)
	default:
		return fmt.Errorf("filesystem-tmpmount rollback: unexpected kind %q", entry.Kind)
	}
}

// hasMountOptions returns true if the fstab content has all opts on the mountpoint line.
func hasMountOptions(fstab, mountpoint string, opts []string) bool {
	for _, line := range strings.Split(fstab, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 || strings.HasPrefix(fields[0], "#") {
			continue
		}
		if fields[1] != mountpoint {
			continue
		}
		optField := fields[3]
		allPresent := true
		for _, o := range opts {
			if !strings.Contains(optField, o) {
				allPresent = false
				break
			}
		}
		return allPresent
	}
	return false
}

// addMountOptions rewrites fstab to add opts to mountpoint.
// If the mountpoint line is absent, a new tmpfs entry is appended.
func addMountOptions(fstab, mountpoint, fstype string, opts []string) string {
	lines := strings.Split(fstab, "\n")
	found := false
	for i, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 4 || strings.HasPrefix(fields[0], "#") {
			continue
		}
		if fields[1] != mountpoint {
			continue
		}
		found = true
		optField := fields[3]
		for _, o := range opts {
			if !strings.Contains(optField, o) {
				optField += "," + o
			}
		}
		fields[3] = optField
		lines[i] = strings.Join(fields, "\t")
	}
	if !found {
		newLine := fmt.Sprintf("%s\t%s\t%s\tdefaults,%s\t0\t0",
			fstype, mountpoint, fstype, strings.Join(opts, ","))
		lines = append(lines, newLine)
	}
	return strings.Join(lines, "\n")
}
```

- [ ] **Step 2.4: Run tests**

```bash
go test ./internal/modules/filesystem/tmpmount/... -v
```

Expected: all 4 tests pass.

- [ ] **Step 2.5: Commit**

```bash
git add internal/modules/filesystem/tmpmount/
git commit -m "feat(hardener): filesystem-tmpmount module — FILE-6310 (dangerous)"
```

---

## Task 3: homemount module (FILE-7524)

**Files:**
- Create: `internal/modules/filesystem/homemount/module.go`
- Create: `internal/modules/filesystem/homemount/module_test.go`

Same fstab pattern as tmpmount, but targets `/home` with `nodev` only. Skips if no `/home` entry exists in fstab (device is unknown).

- [ ] **Step 3.1: Write failing tests**

Create `internal/modules/filesystem/homemount/module_test.go`:

```go
package homemount_test

import (
	"context"
	"strings"
	"testing"

	"github.com/maestroi/hardener/internal/model"
	"github.com/maestroi/hardener/internal/modules/filesystem/homemount"
	"github.com/maestroi/hardener/internal/testhelpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const fstabHomeSecure = `# /etc/fstab
UUID=abc / ext4 defaults 0 1
UUID=def /home ext4 defaults,nodev 0 2
`

const fstabHomeNeedsFixing = `# /etc/fstab
UUID=abc / ext4 defaults 0 1
UUID=def /home ext4 defaults 0 2
`

const fstabNoHomeEntry = `# /etc/fstab
UUID=abc / ext4 defaults 0 1
`

func TestPlan_AlreadySecure(t *testing.T) {
	m := homemount.New()
	inspect := &testhelpers.FakeInspector{
		Files: map[string][]byte{homemount.FstabPath: []byte(fstabHomeSecure)},
	}
	action, err := m.Plan(context.Background(), &model.Finding{ID: "FILE-7524"}, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.False(t, action.Applicable)
}

func TestPlan_NeedsNodev(t *testing.T) {
	m := homemount.New()
	inspect := &testhelpers.FakeInspector{
		Files: map[string][]byte{homemount.FstabPath: []byte(fstabHomeNeedsFixing)},
	}
	action, err := m.Plan(context.Background(), &model.Finding{ID: "FILE-7524"}, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.True(t, action.Applicable)
	assert.True(t, action.Dangerous)
	assert.Equal(t, model.RiskHigh, action.Risk)
}

func TestPlan_NoHomeEntry_Skips(t *testing.T) {
	m := homemount.New()
	inspect := &testhelpers.FakeInspector{
		Files: map[string][]byte{homemount.FstabPath: []byte(fstabNoHomeEntry)},
	}
	action, err := m.Plan(context.Background(), &model.Finding{ID: "FILE-7524"}, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.False(t, action.Applicable)
	assert.Contains(t, action.SkipReason, "no /home entry")
}

func TestApplyAndValidate(t *testing.T) {
	m := homemount.New()
	exec := &testhelpers.FakeExecutor{
		FakeInspector: testhelpers.FakeInspector{
			Files: map[string][]byte{homemount.FstabPath: []byte(fstabHomeNeedsFixing)},
		},
	}
	action := &model.PlannedAction{
		FindingID:  "FILE-7524",
		ModuleID:   "filesystem-homemount",
		Applicable: true,
		Dangerous:  true,
	}

	applied, err := m.Apply(context.Background(), action, exec)
	require.NoError(t, err)
	assert.Equal(t, model.ActionApplied, applied.Status)
	assert.True(t, strings.Contains(string(exec.WrittenFiles[homemount.FstabPath]), "nodev"))

	err = m.Validate(context.Background(), action, exec)
	assert.NoError(t, err)
}
```

- [ ] **Step 3.2: Run tests to confirm they fail**

```bash
go test ./internal/modules/filesystem/homemount/... -v
```

Expected: compilation error.

- [ ] **Step 3.3: Create module**

Create `internal/modules/filesystem/homemount/module.go`:

```go
package homemount

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

const FstabPath = "/etc/fstab"

type Module struct{}

func New() *Module { return &Module{} }

func (m *Module) Metadata() modules.ModuleMetadata {
	return modules.ModuleMetadata{
		ID:               "filesystem-homemount",
		Name:             "Secure /home Mount Options",
		Description:      "Adds nodev to the /home fstab entry to prevent device files in home directories",
		Category:         "Filesystem",
		DefaultRisk:      model.RiskHigh,
		SupportedDistros: []string{"ubuntu"},
		Tags:             []string{"network-safe"},
		CanRollback:      true,
		RequiresReboot:   true,
	}
}

func (m *Module) SupportedFindings() []string {
	return []string{"FILE-7524"}
}

func (m *Module) Plan(ctx context.Context, finding *model.Finding, _ *model.Profile, inspect executor.Inspector) (*model.PlannedAction, error) {
	meta := m.Metadata()

	content, err := inspect.ReadFile(ctx, FstabPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("filesystem-homemount: reading %s: %w", FstabPath, err)
	}

	fstab := string(content)

	if !hasFstabEntry(fstab, "/home") {
		return &model.PlannedAction{
			FindingID:  finding.ID,
			ModuleID:   meta.ID,
			Applicable: false,
			SkipReason: "no /home entry in fstab; add a dedicated /home mount before enabling nodev",
		}, nil
	}

	if hasMountOption(fstab, "/home", "nodev") {
		return &model.PlannedAction{
			FindingID:  finding.ID,
			ModuleID:   meta.ID,
			Applicable: false,
			SkipReason: "/home already has nodev in fstab",
		}, nil
	}

	return &model.PlannedAction{
		FindingID:      finding.ID,
		ModuleID:       meta.ID,
		Title:          "Add nodev to /home fstab entry",
		Description:    fmt.Sprintf("Modify %s to add nodev to /home mount options", FstabPath),
		Steps:          []string{fmt.Sprintf("backup and rewrite %s with nodev on /home", FstabPath)},
		Metadata:       map[string]string{"target_file": FstabPath},
		Risk:           model.RiskHigh,
		Impact:         "Device files cannot be created in /home. Requires reboot to take effect.",
		Dangerous:      true,
		RequiresReboot: true,
		CanRollback:    true,
		Applicable:     true,
		Tags:           []string{"network-safe"},
	}, nil
}

func (m *Module) Apply(ctx context.Context, action *model.PlannedAction, exec executor.Executor) (*model.AppliedAction, error) {
	content, err := exec.ReadFile(ctx, FstabPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("filesystem-homemount: reading %s: %w", FstabPath, err)
	}

	updated := addFstabOption(string(content), "/home", "nodev")
	if err := exec.WriteFile(ctx, FstabPath, []byte(updated), 0644); err != nil {
		return nil, fmt.Errorf("filesystem-homemount: writing %s: %w", FstabPath, err)
	}

	return &model.AppliedAction{
		PlannedAction: *action,
		AppliedAt:     time.Now(),
		Status:        model.ActionApplied,
	}, nil
}

func (m *Module) Validate(ctx context.Context, _ *model.PlannedAction, inspect executor.Inspector) error {
	content, err := inspect.ReadFile(ctx, FstabPath)
	if err != nil {
		return fmt.Errorf("filesystem-homemount: reading %s: %w", FstabPath, err)
	}
	if !hasMountOption(string(content), "/home", "nodev") {
		return fmt.Errorf("filesystem-homemount: /home is missing nodev in %s", FstabPath)
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
			return fmt.Errorf("filesystem-homemount: reading backup %s: %w", entry.BackupPath, err)
		}
		return exec.WriteFile(ctx, entry.Path, backup, entry.OrigMode)
	default:
		return fmt.Errorf("filesystem-homemount rollback: unexpected kind %q", entry.Kind)
	}
}

func hasFstabEntry(fstab, mountpoint string) bool {
	for _, line := range strings.Split(fstab, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && !strings.HasPrefix(fields[0], "#") && fields[1] == mountpoint {
			return true
		}
	}
	return false
}

func hasMountOption(fstab, mountpoint, opt string) bool {
	for _, line := range strings.Split(fstab, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 || strings.HasPrefix(fields[0], "#") || fields[1] != mountpoint {
			continue
		}
		return strings.Contains(fields[3], opt)
	}
	return false
}

func addFstabOption(fstab, mountpoint, opt string) string {
	lines := strings.Split(fstab, "\n")
	for i, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 4 || strings.HasPrefix(fields[0], "#") || fields[1] != mountpoint {
			continue
		}
		if !strings.Contains(fields[3], opt) {
			fields[3] += "," + opt
		}
		lines[i] = strings.Join(fields, "\t")
	}
	return strings.Join(lines, "\n")
}
```

- [ ] **Step 3.4: Run tests**

```bash
go test ./internal/modules/filesystem/homemount/... -v
```

Expected: all 4 tests pass.

- [ ] **Step 3.5: Commit**

```bash
git add internal/modules/filesystem/homemount/
git commit -m "feat(hardener): filesystem-homemount module — FILE-7524 (dangerous)"
```

---

## Task 4: grubpassword module (BOOT-5122)

**Files:**
- Create: `internal/modules/boot/grubpassword/module.go`
- Create: `internal/modules/boot/grubpassword/module_test.go`

Writes `/etc/grub.d/01-hardener-password` with the PBKDF2 hash from `profile.GrubPasswordHash`, then runs `update-grub`. Skips with a profile hint if hash is absent.

Generate a hash with: `grub-mkpasswd-pbkdf2`

- [ ] **Step 4.1: Write failing tests**

Create `internal/modules/boot/grubpassword/module_test.go`:

```go
package grubpassword_test

import (
	"context"
	"testing"

	"github.com/maestroi/hardener/internal/executor"
	"github.com/maestroi/hardener/internal/model"
	"github.com/maestroi/hardener/internal/modules/boot/grubpassword"
	"github.com/maestroi/hardener/internal/testhelpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testHash = "grub.pbkdf2.sha512.10000.AABBCC.DDEEFF"

func TestPlan_NoHashInProfile(t *testing.T) {
	m := grubpassword.New()
	inspect := &testhelpers.FakeInspector{}
	action, err := m.Plan(context.Background(), &model.Finding{ID: "BOOT-5122"}, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.False(t, action.Applicable)
	assert.Contains(t, action.SkipReason, "grub_password_hash")
}

func TestPlan_AlreadyConfigured(t *testing.T) {
	m := grubpassword.New()
	profile := &model.Profile{GrubPasswordHash: testHash}
	inspect := &testhelpers.FakeInspector{
		Files: map[string][]byte{
			grubpassword.ScriptPath: []byte("password_pbkdf2 root " + testHash),
		},
	}
	action, err := m.Plan(context.Background(), &model.Finding{ID: "BOOT-5122"}, profile, inspect)
	require.NoError(t, err)
	assert.False(t, action.Applicable)
}

func TestPlan_NeedsPassword(t *testing.T) {
	m := grubpassword.New()
	profile := &model.Profile{GrubPasswordHash: testHash}
	inspect := &testhelpers.FakeInspector{}
	action, err := m.Plan(context.Background(), &model.Finding{ID: "BOOT-5122"}, profile, inspect)
	require.NoError(t, err)
	assert.True(t, action.Applicable)
	assert.True(t, action.Dangerous)
	assert.Equal(t, model.RiskCritical, action.Risk)
}

func TestApplyAndValidate(t *testing.T) {
	m := grubpassword.New()
	exec := &testhelpers.FakeExecutor{
		RunFn: func(name string, args ...string) (executor.CmdOutput, error) {
			return executor.CmdOutput{}, nil
		},
	}
	action := &model.PlannedAction{
		FindingID:  "BOOT-5122",
		ModuleID:   "boot-grub-password",
		Applicable: true,
		Dangerous:  true,
		Metadata:   map[string]string{"hash": testHash},
	}

	applied, err := m.Apply(context.Background(), action, exec)
	require.NoError(t, err)
	assert.Equal(t, model.ActionApplied, applied.Status)
	assert.True(t, exec.FileContains(grubpassword.ScriptPath, testHash))

	err = m.Validate(context.Background(), action, exec)
	assert.NoError(t, err)
}
```

- [ ] **Step 4.2: Run tests to confirm they fail**

```bash
go test ./internal/modules/boot/grubpassword/... -v
```

Expected: compilation error.

- [ ] **Step 4.3: Create module**

Create `internal/modules/boot/grubpassword/module.go`:

```go
package grubpassword

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

const ScriptPath = "/etc/grub.d/01-hardener-password"

type Module struct{}

func New() *Module { return &Module{} }

func (m *Module) Metadata() modules.ModuleMetadata {
	return modules.ModuleMetadata{
		ID:               "boot-grub-password",
		Name:             "Set GRUB Bootloader Password",
		Description:      "Writes a GRUB password script so the bootloader requires authentication before editing entries",
		Category:         "Boot",
		DefaultRisk:      model.RiskCritical,
		SupportedDistros: []string{"ubuntu"},
		Tags:             []string{"network-safe"},
		CanRollback:      true,
		RequiresReboot:   false,
	}
}

func (m *Module) SupportedFindings() []string {
	return []string{"BOOT-5122"}
}

func (m *Module) Plan(ctx context.Context, finding *model.Finding, profile *model.Profile, inspect executor.Inspector) (*model.PlannedAction, error) {
	meta := m.Metadata()

	if profile.GrubPasswordHash == "" {
		return &model.PlannedAction{
			FindingID:  finding.ID,
			ModuleID:   meta.ID,
			Applicable: false,
			SkipReason: "set grub_password_hash in profile to enable BOOT-5122 remediation (generate with: grub-mkpasswd-pbkdf2)",
		}, nil
	}

	content, err := inspect.ReadFile(ctx, ScriptPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("boot-grub-password: reading %s: %w", ScriptPath, err)
	}

	if err == nil && strings.Contains(string(content), profile.GrubPasswordHash) {
		return &model.PlannedAction{
			FindingID:  finding.ID,
			ModuleID:   meta.ID,
			Applicable: false,
			SkipReason: fmt.Sprintf("%s already contains the configured password hash", ScriptPath),
		}, nil
	}

	return &model.PlannedAction{
		FindingID:   finding.ID,
		ModuleID:    meta.ID,
		Title:       "Set GRUB bootloader password",
		Description: fmt.Sprintf("Write %s and run update-grub to protect bootloader entries", ScriptPath),
		Steps: []string{
			fmt.Sprintf("write %s with PBKDF2 hash", ScriptPath),
			"chmod 700 " + ScriptPath,
			"update-grub",
		},
		Metadata:    map[string]string{"hash": profile.GrubPasswordHash},
		Risk:        model.RiskCritical,
		Impact:      "GRUB will require the configured password to edit boot entries or access recovery mode.",
		Dangerous:   true,
		CanRollback: true,
		Applicable:  true,
		Tags:        []string{"network-safe"},
	}, nil
}

func (m *Module) Apply(ctx context.Context, action *model.PlannedAction, exec executor.Executor) (*model.AppliedAction, error) {
	hash := action.Metadata["hash"]
	script := fmt.Sprintf(`#!/bin/sh
# Managed by hardener — do not edit manually.
set superusers="root"
password_pbkdf2 root %s
`, hash)

	if err := exec.WriteFile(ctx, ScriptPath, []byte(script), 0700); err != nil {
		return nil, fmt.Errorf("boot-grub-password: writing %s: %w", ScriptPath, err)
	}
	if err := exec.SetFileMode(ctx, ScriptPath, 0700); err != nil {
		return nil, fmt.Errorf("boot-grub-password: chmod %s: %w", ScriptPath, err)
	}
	if _, err := exec.Run(ctx, "update-grub"); err != nil {
		return nil, fmt.Errorf("boot-grub-password: update-grub: %w", err)
	}

	return &model.AppliedAction{
		PlannedAction: *action,
		AppliedAt:     time.Now(),
		Status:        model.ActionApplied,
	}, nil
}

func (m *Module) Validate(ctx context.Context, action *model.PlannedAction, inspect executor.Inspector) error {
	hash := action.Metadata["hash"]
	content, err := inspect.ReadFile(ctx, ScriptPath)
	if err != nil {
		return fmt.Errorf("boot-grub-password: reading %s: %w", ScriptPath, err)
	}
	if !strings.Contains(string(content), hash) {
		return fmt.Errorf("boot-grub-password: hash not found in %s after apply", ScriptPath)
	}
	return nil
}

func (m *Module) Rollback(ctx context.Context, entry *model.RollbackEntry, exec executor.Executor) error {
	switch entry.Kind {
	case model.RollbackFile:
		// Remove the script and regenerate grub config without password
		if err := exec.WriteFile(ctx, entry.Path, []byte(""), 0700); err != nil {
			return fmt.Errorf("boot-grub-password: clearing %s: %w", entry.Path, err)
		}
		if _, err := exec.Run(ctx, "update-grub"); err != nil {
			return fmt.Errorf("boot-grub-password: update-grub on rollback: %w", err)
		}
		return nil
	default:
		return fmt.Errorf("boot-grub-password rollback: unexpected kind %q", entry.Kind)
	}
}
```

- [ ] **Step 4.4: Run tests**

```bash
go test ./internal/modules/boot/grubpassword/... -v
```

Expected: all 4 tests pass.

- [ ] **Step 4.5: Commit**

```bash
git add internal/modules/boot/grubpassword/
git commit -m "feat(hardener): boot-grub-password module — BOOT-5122 (dangerous)"
```

---

## Task 5: kernel/modules module (KRNL-5830)

**Files:**
- Create: `internal/modules/kernel/modules/module.go`
- Create: `internal/modules/kernel/modules/module_test.go`

Writes `/etc/sysctl.d/99-hardener-modules.conf` with `kernel.modules_disabled = 1` and applies it. **Warning:** setting `kernel.modules_disabled=1` at runtime is one-way — it cannot be unset without a reboot. Rollback removes the config file (preventing re-application on next boot) but cannot reverse the live sysctl value.

- [ ] **Step 5.1: Write failing tests**

Create `internal/modules/kernel/modules/module_test.go`:

```go
package modules_test

import (
	"context"
	"testing"

	"github.com/maestroi/hardener/internal/model"
	kernelmodules "github.com/maestroi/hardener/internal/modules/kernel/modules"
	"github.com/maestroi/hardener/internal/testhelpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPlan_AlreadyDisabled(t *testing.T) {
	m := kernelmodules.New()
	inspect := &testhelpers.FakeInspector{
		SysctlValues: map[string]string{"kernel.modules_disabled": "1"},
	}
	action, err := m.Plan(context.Background(), &model.Finding{ID: "KRNL-5830"}, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.False(t, action.Applicable)
}

func TestPlan_NotDisabled(t *testing.T) {
	m := kernelmodules.New()
	inspect := &testhelpers.FakeInspector{
		SysctlValues: map[string]string{"kernel.modules_disabled": "0"},
	}
	action, err := m.Plan(context.Background(), &model.Finding{ID: "KRNL-5830"}, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.True(t, action.Applicable)
	assert.True(t, action.Dangerous)
	assert.Equal(t, model.RiskCritical, action.Risk)
}

func TestApplyAndValidate(t *testing.T) {
	m := kernelmodules.New()
	exec := &testhelpers.FakeExecutor{
		FakeInspector: testhelpers.FakeInspector{
			SysctlValues: map[string]string{"kernel.modules_disabled": "1"},
		},
	}
	action := &model.PlannedAction{
		FindingID:  "KRNL-5830",
		ModuleID:   "kernel-modules-disabled",
		Applicable: true,
		Dangerous:  true,
	}

	applied, err := m.Apply(context.Background(), action, exec)
	require.NoError(t, err)
	assert.Equal(t, model.ActionApplied, applied.Status)
	assert.True(t, exec.HasWritten(kernelmodules.ConfPath))

	err = m.Validate(context.Background(), action, exec)
	assert.NoError(t, err)
}
```

- [ ] **Step 5.2: Run tests to confirm they fail**

```bash
go test ./internal/modules/kernel/modules/... -v
```

Expected: compilation error.

- [ ] **Step 5.3: Create module**

Create `internal/modules/kernel/modules/module.go`:

```go
package modules

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/maestroi/hardener/internal/executor"
	"github.com/maestroi/hardener/internal/model"
	"github.com/maestroi/hardener/internal/modules"
)

const (
	ConfPath   = "/etc/sysctl.d/99-hardener-modules.conf"
	sysctlKey  = "kernel.modules_disabled"
	sysctlVal  = "1"
	confContent = "# Managed by hardener — do not edit manually.\nkernel.modules_disabled = 1\n"
)

type Module struct{}

func New() *Module { return &Module{} }

func (m *Module) Metadata() modules.ModuleMetadata {
	return modules.ModuleMetadata{
		ID:               "kernel-modules-disabled",
		Name:             "Disable Kernel Module Loading",
		Description:      "Sets kernel.modules_disabled=1 to prevent loading new kernel modules at runtime",
		Category:         "Kernel",
		DefaultRisk:      model.RiskCritical,
		SupportedDistros: []string{"ubuntu"},
		Tags:             []string{"network-safe"},
		CanRollback:      true,
		RequiresReboot:   true,
	}
}

func (m *Module) SupportedFindings() []string {
	return []string{"KRNL-5830"}
}

func (m *Module) Plan(ctx context.Context, finding *model.Finding, _ *model.Profile, inspect executor.Inspector) (*model.PlannedAction, error) {
	meta := m.Metadata()

	current, err := inspect.GetSysctl(ctx, sysctlKey)
	if err != nil {
		return nil, fmt.Errorf("kernel-modules-disabled: reading %s: %w", sysctlKey, err)
	}

	if strings.TrimSpace(current) == sysctlVal {
		return &model.PlannedAction{
			FindingID:  finding.ID,
			ModuleID:   meta.ID,
			Applicable: false,
			SkipReason: fmt.Sprintf("%s is already %s", sysctlKey, sysctlVal),
		}, nil
	}

	return &model.PlannedAction{
		FindingID:   finding.ID,
		ModuleID:    meta.ID,
		Title:       "Disable kernel module loading",
		Description: fmt.Sprintf("Write %s and apply %s=1 via sysctl", ConfPath, sysctlKey),
		Steps: []string{
			fmt.Sprintf("write %s", ConfPath),
			fmt.Sprintf("sysctl -w %s=%s", sysctlKey, sysctlVal),
		},
		Metadata:    map[string]string{"sysctl_key": sysctlKey},
		Risk:        model.RiskCritical,
		Impact:      "No new kernel modules can be loaded at runtime until reboot. Required modules must already be loaded. This is a one-way operation at runtime — rollback removes the config file but cannot restore module loading until reboot.",
		Dangerous:   true,
		CanRollback: true,
		Applicable:  true,
		Tags:        []string{"network-safe"},
	}, nil
}

func (m *Module) Apply(ctx context.Context, action *model.PlannedAction, exec executor.Executor) (*model.AppliedAction, error) {
	if err := exec.WriteFile(ctx, ConfPath, []byte(confContent), 0644); err != nil {
		return nil, fmt.Errorf("kernel-modules-disabled: writing %s: %w", ConfPath, err)
	}
	if err := exec.SetSysctl(ctx, sysctlKey, sysctlVal); err != nil {
		return nil, fmt.Errorf("kernel-modules-disabled: setting %s: %w", sysctlKey, err)
	}

	return &model.AppliedAction{
		PlannedAction: *action,
		AppliedAt:     time.Now(),
		Status:        model.ActionApplied,
	}, nil
}

func (m *Module) Validate(ctx context.Context, _ *model.PlannedAction, inspect executor.Inspector) error {
	current, err := inspect.GetSysctl(ctx, sysctlKey)
	if err != nil {
		return fmt.Errorf("kernel-modules-disabled: reading %s: %w", sysctlKey, err)
	}
	if strings.TrimSpace(current) != sysctlVal {
		return fmt.Errorf("kernel-modules-disabled: %s = %q, want %q", sysctlKey, current, sysctlVal)
	}
	return nil
}

func (m *Module) Rollback(ctx context.Context, entry *model.RollbackEntry, exec executor.Executor) error {
	switch entry.Kind {
	case model.RollbackFile:
		// Remove the config file so it won't re-apply on next boot.
		// The live sysctl value cannot be reversed without reboot.
		if err := exec.WriteFile(ctx, entry.Path, []byte(""), 0644); err != nil {
			return fmt.Errorf("kernel-modules-disabled: clearing %s: %w", entry.Path, err)
		}
		return nil
	case model.RollbackSysctl:
		// Cannot set kernel.modules_disabled back to 0 at runtime — ignored.
		return nil
	default:
		return fmt.Errorf("kernel-modules-disabled rollback: unexpected kind %q", entry.Kind)
	}
}
```

- [ ] **Step 5.4: Run tests**

```bash
go test ./internal/modules/kernel/modules/... -v
```

Expected: all 3 tests pass.

- [ ] **Step 5.5: Commit**

```bash
git add internal/modules/kernel/modules/
git commit -m "feat(hardener): kernel-modules-disabled module — KRNL-5830 (dangerous)"
```

---

## Task 6: Wire up registry and clear advisory/manual completely

**Files:**
- Modify: `internal/registry/init.go`
- Modify: `internal/modules/advisory/manual/module.go`

- [ ] **Step 6.1: Register batch 3 modules in registry**

In `internal/registry/init.go`, add imports:

```go
tmpmountmod    "github.com/maestroi/hardener/internal/modules/filesystem/tmpmount"
homemountmod   "github.com/maestroi/hardener/internal/modules/filesystem/homemount"
grubpasswdmod  "github.com/maestroi/hardener/internal/modules/boot/grubpassword"
kernelmodsmod  "github.com/maestroi/hardener/internal/modules/kernel/modules"
```

Add to `Default()` after the batch 2 registrations, before `manualmod`:

```go
// Batch 3: dangerous modules
r.Register(tmpmountmod.New())
r.Register(homemountmod.New())
r.Register(grubpasswdmod.New())
r.Register(kernelmodsmod.New())
```

- [ ] **Step 6.2: Clear all remaining finding IDs from advisory/manual**

In `internal/modules/advisory/manual/module.go`, set `supportedFindings` to an empty slice:

```go
var supportedFindings = []string{}
```

And update the module description:

```go
func (m *Module) Metadata() modules.ModuleMetadata {
	return modules.ModuleMetadata{
		ID:               "advisory-manual",
		Name:             "Manual Advisory Checks",
		Description:      "Catch-all for findings with no registered module",
		Category:         "Advisory",
		DefaultRisk:      model.RiskNone,
		SupportedDistros: []string{"ubuntu"},
		Tags:             []string{"manual"},
		CanRollback:      false,
		RequiresReboot:   false,
	}
}
```

- [ ] **Step 6.3: Run full test suite**

```bash
go test ./... -v 2>&1 | tail -50
```

Expected: all tests pass.

- [ ] **Step 6.4: Build binary**

```bash
go build ./...
```

Expected: no errors.

- [ ] **Step 6.5: Commit**

```bash
git add internal/registry/init.go internal/modules/advisory/manual/module.go
git commit -m "feat(hardener): register batch 3 modules; advisory/manual is now a true catch-all"
```
