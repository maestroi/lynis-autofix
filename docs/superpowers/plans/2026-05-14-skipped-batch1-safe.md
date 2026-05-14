# Skipped Findings — Batch 1 (Safe) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement 8 low/medium-risk remediation modules covering DEB-0280, DEB-0880, DEB-0810, DEB-0811, FINT-4350, FIRE-4513, BOOT-5264, USB-1000, HRDN-7230, NETW-3200 — removing all 10 findings from the advisory/manual catch-all.

**Architecture:** Each module is stateless and implements the `modules.Module` interface. All file-writing modules use `RollbackFile` entries. Package installs use the existing no-op rollback pattern. Modules that need shell command output in Plan/Validate use `RunReadOnly`. A small FakeInspector enhancement is added first to support RunReadOnly-dependent tests.

**Tech Stack:** Go 1.22, `github.com/maestroi/hardener`, testify.

---

## File Map

| File | Action | Purpose |
|------|--------|---------|
| `internal/testhelpers/fakes.go` | Modify | Add `RunReadOnlyFn` to FakeInspector + `SetFileModeRecords` to FakeExecutor |
| `internal/modules/packages/aptconfig/module.go` | Create | DEB-0280 + DEB-0880: write APT periodic config |
| `internal/modules/packages/aptconfig/module_test.go` | Create | Tests for aptconfig |
| `internal/modules/packages/debpurge/module.go` | Create | DEB-0810: purge removed-not-purged packages |
| `internal/modules/packages/debpurge/module_test.go` | Create | Tests for debpurge |
| `internal/modules/packages/debsecan/module.go` | Create | DEB-0811: install debsecan |
| `internal/modules/packages/debsecan/module_test.go` | Create | Tests for debsecan |
| `internal/modules/packages/aide/module.go` | Create | FINT-4350: install aide + init DB |
| `internal/modules/packages/aide/module_test.go` | Create | Tests for aide |
| `internal/modules/network/firewall/module.go` | Create | FIRE-4513: install + enable UFW |
| `internal/modules/network/firewall/module_test.go` | Create | Tests for firewall |
| `internal/modules/boot/grubperms/module.go` | Create | BOOT-5264: chmod 600 /boot/grub/grub.cfg |
| `internal/modules/boot/grubperms/module_test.go` | Create | Tests for grubperms |
| `internal/modules/kernel/usbstorage/module.go` | Create | USB-1000 + HRDN-7230: blacklist usb-storage |
| `internal/modules/kernel/usbstorage/module_test.go` | Create | Tests for usbstorage |
| `internal/modules/kernel/protocols/module.go` | Create | NETW-3200: blacklist dccp/sctp/rds/tipc |
| `internal/modules/kernel/protocols/module_test.go` | Create | Tests for protocols |
| `internal/registry/init.go` | Modify | Register 8 new modules |
| `internal/modules/advisory/manual/module.go` | Modify | Remove 10 finding IDs now handled by real modules |

---

## Task 1: Enhance test helpers

**Files:**
- Modify: `internal/testhelpers/fakes.go`

- [ ] **Step 1.1: Add RunReadOnlyFn to FakeInspector and SetFileModeRecords to FakeExecutor**

In `internal/testhelpers/fakes.go`, add `RunReadOnlyFn` to `FakeInspector` and override `RunReadOnly` on `FakeExecutor`. Also add `SetFileModeRecords` to `FakeExecutor`.

Replace the existing `RunReadOnly` method on `FakeInspector`:

```go
// RunReadOnlyFn optionally overrides RunReadOnly(). If nil, returns empty CmdOutput.
RunReadOnlyFn func(name string, args ...string) (executor.CmdOutput, error)
```

Add this field to the `FakeInspector` struct (after `SysctlValues`), then change:

```go
func (f *FakeInspector) RunReadOnly(_ context.Context, _ string, _ ...string) (executor.CmdOutput, error) {
	return executor.CmdOutput{}, nil
}
```

to:

```go
func (f *FakeInspector) RunReadOnly(_ context.Context, name string, args ...string) (executor.CmdOutput, error) {
	if f.RunReadOnlyFn != nil {
		return f.RunReadOnlyFn(name, args...)
	}
	return executor.CmdOutput{}, nil
}
```

Add `SetFileModeRecords map[string]fs.FileMode` field to `FakeExecutor` struct (after `RestartedServices`). Then replace:

```go
func (f *FakeExecutor) SetFileMode(_ context.Context, _ string, _ os.FileMode) error { return nil }
```

with:

```go
func (f *FakeExecutor) SetFileMode(_ context.Context, path string, mode os.FileMode) error {
	if f.SetFileModeRecords == nil {
		f.SetFileModeRecords = make(map[string]os.FileMode)
	}
	f.SetFileModeRecords[path] = mode
	return nil
}
```

- [ ] **Step 1.2: Run existing tests to confirm nothing broke**

```bash
go test ./internal/testhelpers/... -v
```

Expected: all tests pass.

- [ ] **Step 1.3: Commit**

```bash
git add internal/testhelpers/fakes.go
git commit -m "test: add RunReadOnlyFn and SetFileModeRecords to fake helpers"
```

---

## Task 2: aptconfig module (DEB-0280, DEB-0880)

**Files:**
- Create: `internal/modules/packages/aptconfig/module.go`
- Create: `internal/modules/packages/aptconfig/module_test.go`

- [ ] **Step 2.1: Write failing tests**

Create `internal/modules/packages/aptconfig/module_test.go`:

```go
package aptconfig_test

import (
	"context"
	"testing"

	"github.com/maestroi/hardener/internal/model"
	"github.com/maestroi/hardener/internal/modules/packages/aptconfig"
	"github.com/maestroi/hardener/internal/testhelpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPlan_AlreadyCompliant(t *testing.T) {
	m := aptconfig.New()
	inspect := &testhelpers.FakeInspector{
		Files: map[string][]byte{
			aptconfig.ConfPath: []byte(aptconfig.ConfContent),
		},
	}
	action, err := m.Plan(context.Background(), &model.Finding{ID: "DEB-0280"}, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.False(t, action.Applicable)
	assert.NotEmpty(t, action.SkipReason)
}

func TestPlan_NotPresent(t *testing.T) {
	m := aptconfig.New()
	inspect := &testhelpers.FakeInspector{}
	action, err := m.Plan(context.Background(), &model.Finding{ID: "DEB-0880"}, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.True(t, action.Applicable)
	assert.Equal(t, model.RiskLow, action.Risk)
}

func TestApplyAndValidate(t *testing.T) {
	m := aptconfig.New()
	exec := &testhelpers.FakeExecutor{}

	action := &model.PlannedAction{FindingID: "DEB-0280", ModuleID: "pkgs-apt-config", Applicable: true}
	applied, err := m.Apply(context.Background(), action, exec)
	require.NoError(t, err)
	assert.Equal(t, model.ActionApplied, applied.Status)
	assert.True(t, exec.HasWritten(aptconfig.ConfPath))

	err = m.Validate(context.Background(), action, exec)
	assert.NoError(t, err)
}
```

- [ ] **Step 2.2: Run tests to confirm they fail**

```bash
go test ./internal/modules/packages/aptconfig/... -v
```

Expected: compilation error (package doesn't exist yet).

- [ ] **Step 2.3: Create module**

Create `internal/modules/packages/aptconfig/module.go`:

```go
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
```

- [ ] **Step 2.4: Run tests**

```bash
go test ./internal/modules/packages/aptconfig/... -v
```

Expected: all 3 tests pass.

- [ ] **Step 2.5: Commit**

```bash
git add internal/modules/packages/aptconfig/
git commit -m "feat(hardener): pkgs-apt-config module — DEB-0280, DEB-0880"
```

---

## Task 3: debpurge module (DEB-0810)

**Files:**
- Create: `internal/modules/packages/debpurge/module.go`
- Create: `internal/modules/packages/debpurge/module_test.go`

- [ ] **Step 3.1: Write failing tests**

Create `internal/modules/packages/debpurge/module_test.go`:

```go
package debpurge_test

import (
	"context"
	"testing"

	"github.com/maestroi/hardener/internal/executor"
	"github.com/maestroi/hardener/internal/model"
	"github.com/maestroi/hardener/internal/modules/packages/debpurge"
	"github.com/maestroi/hardener/internal/testhelpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPlan_NothingToPurge(t *testing.T) {
	m := debpurge.New()
	inspect := &testhelpers.FakeInspector{
		RunReadOnlyFn: func(name string, args ...string) (executor.CmdOutput, error) {
			return executor.CmdOutput{Stdout: ""}, nil
		},
	}
	action, err := m.Plan(context.Background(), &model.Finding{ID: "DEB-0810"}, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.False(t, action.Applicable)
	assert.NotEmpty(t, action.SkipReason)
}

func TestPlan_HasRcPackages(t *testing.T) {
	m := debpurge.New()
	dpkgOutput := "rc  old-package  1.0  all  An old package\nrc  another-pkg  2.0  amd64  Another\n"
	inspect := &testhelpers.FakeInspector{
		RunReadOnlyFn: func(name string, args ...string) (executor.CmdOutput, error) {
			return executor.CmdOutput{Stdout: dpkgOutput}, nil
		},
	}
	action, err := m.Plan(context.Background(), &model.Finding{ID: "DEB-0810"}, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.True(t, action.Applicable)
	assert.Contains(t, action.Metadata["rc_packages"], "old-package")
	assert.Contains(t, action.Metadata["rc_packages"], "another-pkg")
}

func TestApply_PurgesPackages(t *testing.T) {
	m := debpurge.New()
	exec := &testhelpers.FakeExecutor{
		RunFn: func(name string, args ...string) (executor.CmdOutput, error) {
			return executor.CmdOutput{}, nil
		},
	}
	action := &model.PlannedAction{
		FindingID:  "DEB-0810",
		ModuleID:   "pkgs-debpurge",
		Applicable: true,
		Metadata:   map[string]string{"rc_packages": "old-package,another-pkg"},
	}
	applied, err := m.Apply(context.Background(), action, exec)
	require.NoError(t, err)
	assert.Equal(t, model.ActionApplied, applied.Status)
}
```

- [ ] **Step 3.2: Run tests to confirm they fail**

```bash
go test ./internal/modules/packages/debpurge/... -v
```

Expected: compilation error.

- [ ] **Step 3.3: Create module**

Create `internal/modules/packages/debpurge/module.go`:

```go
package debpurge

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/maestroi/hardener/internal/executor"
	"github.com/maestroi/hardener/internal/model"
	"github.com/maestroi/hardener/internal/modules"
)

type Module struct{}

func New() *Module { return &Module{} }

func (m *Module) Metadata() modules.ModuleMetadata {
	return modules.ModuleMetadata{
		ID:               "pkgs-debpurge",
		Name:             "Purge Removed Packages",
		Description:      "Purges packages in removed-but-not-purged state (dpkg rc) to eliminate leftover config files",
		Category:         "Packages",
		DefaultRisk:      model.RiskLow,
		SupportedDistros: []string{"ubuntu"},
		Tags:             []string{"network-safe", "docker-safe"},
		CanRollback:      false,
		RequiresReboot:   false,
	}
}

func (m *Module) SupportedFindings() []string {
	return []string{"DEB-0810"}
}

func (m *Module) Plan(ctx context.Context, finding *model.Finding, _ *model.Profile, inspect executor.Inspector) (*model.PlannedAction, error) {
	meta := m.Metadata()

	out, err := inspect.RunReadOnly(ctx, "dpkg", "--list")
	if err != nil {
		return nil, fmt.Errorf("pkgs-debpurge: running dpkg --list: %w", err)
	}

	var rcPkgs []string
	for _, line := range strings.Split(out.Stdout, "\n") {
		if strings.HasPrefix(line, "rc ") || strings.HasPrefix(line, "rc\t") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				rcPkgs = append(rcPkgs, fields[1])
			}
		}
	}

	if len(rcPkgs) == 0 {
		return &model.PlannedAction{
			FindingID:  finding.ID,
			ModuleID:   meta.ID,
			Applicable: false,
			SkipReason: "no removed-but-not-purged packages found",
		}, nil
	}

	return &model.PlannedAction{
		FindingID:   finding.ID,
		ModuleID:    meta.ID,
		Title:       "Purge removed packages",
		Description: fmt.Sprintf("Purge %d removed packages: %s", len(rcPkgs), strings.Join(rcPkgs, ", ")),
		Steps:       []string{fmt.Sprintf("dpkg --purge %s", strings.Join(rcPkgs, " "))},
		Metadata:    map[string]string{"rc_packages": strings.Join(rcPkgs, ",")},
		Risk:        model.RiskLow,
		CanRollback: false,
		Applicable:  true,
		Tags:        []string{"network-safe", "docker-safe"},
	}, nil
}

func (m *Module) Apply(ctx context.Context, action *model.PlannedAction, exec executor.Executor) (*model.AppliedAction, error) {
	pkgList := action.Metadata["rc_packages"]
	if pkgList == "" {
		return &model.AppliedAction{
			PlannedAction: *action,
			AppliedAt:     time.Now(),
			Status:        model.ActionApplied,
		}, nil
	}

	for _, pkg := range strings.Split(pkgList, ",") {
		pkg = strings.TrimSpace(pkg)
		if pkg == "" {
			continue
		}
		if _, err := exec.Run(ctx, "dpkg", "--purge", pkg); err != nil {
			return nil, fmt.Errorf("pkgs-debpurge: purging %s: %w", pkg, err)
		}
	}

	return &model.AppliedAction{
		PlannedAction: *action,
		AppliedAt:     time.Now(),
		Status:        model.ActionApplied,
	}, nil
}

func (m *Module) Validate(ctx context.Context, _ *model.PlannedAction, inspect executor.Inspector) error {
	out, err := inspect.RunReadOnly(ctx, "dpkg", "--list")
	if err != nil {
		return fmt.Errorf("pkgs-debpurge: running dpkg --list: %w", err)
	}
	for _, line := range strings.Split(out.Stdout, "\n") {
		if strings.HasPrefix(line, "rc ") || strings.HasPrefix(line, "rc\t") {
			return fmt.Errorf("pkgs-debpurge: removed-not-purged packages still present after apply")
		}
	}
	return nil
}

func (m *Module) Rollback(_ context.Context, entry *model.RollbackEntry, _ executor.Executor) error {
	switch entry.Kind {
	case model.RollbackPackage:
		return nil // purged packages cannot be un-purged
	default:
		return fmt.Errorf("pkgs-debpurge rollback: unexpected kind %q", entry.Kind)
	}
}
```

- [ ] **Step 3.4: Run tests**

```bash
go test ./internal/modules/packages/debpurge/... -v
```

Expected: all 3 tests pass.

- [ ] **Step 3.5: Commit**

```bash
git add internal/modules/packages/debpurge/
git commit -m "feat(hardener): pkgs-debpurge module — DEB-0810"
```

---

## Task 4: debsecan module (DEB-0811)

**Files:**
- Create: `internal/modules/packages/debsecan/module.go`
- Create: `internal/modules/packages/debsecan/module_test.go`

- [ ] **Step 4.1: Write failing tests**

Create `internal/modules/packages/debsecan/module_test.go`:

```go
package debsecan_test

import (
	"context"
	"testing"

	"github.com/maestroi/hardener/internal/model"
	"github.com/maestroi/hardener/internal/modules/packages/debsecan"
	"github.com/maestroi/hardener/internal/testhelpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPlan_AlreadyInstalled(t *testing.T) {
	m := debsecan.New()
	inspect := &testhelpers.FakeInspector{
		InstalledPkgs: map[string]bool{"debsecan": true},
	}
	action, err := m.Plan(context.Background(), &model.Finding{ID: "DEB-0811"}, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.False(t, action.Applicable)
	assert.NotEmpty(t, action.SkipReason)
}

func TestPlan_NotInstalled(t *testing.T) {
	m := debsecan.New()
	inspect := &testhelpers.FakeInspector{}
	action, err := m.Plan(context.Background(), &model.Finding{ID: "DEB-0811"}, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.True(t, action.Applicable)
}

func TestApplyAndValidate(t *testing.T) {
	m := debsecan.New()
	exec := &testhelpers.FakeExecutor{}
	action := &model.PlannedAction{FindingID: "DEB-0811", ModuleID: "pkgs-debsecan", Applicable: true}

	applied, err := m.Apply(context.Background(), action, exec)
	require.NoError(t, err)
	assert.Equal(t, model.ActionApplied, applied.Status)
	assert.True(t, exec.PackageInstalled("debsecan"))

	err = m.Validate(context.Background(), action, exec)
	assert.NoError(t, err)
}
```

- [ ] **Step 4.2: Run tests to confirm they fail**

```bash
go test ./internal/modules/packages/debsecan/... -v
```

Expected: compilation error.

- [ ] **Step 4.3: Create module**

Create `internal/modules/packages/debsecan/module.go`:

```go
package debsecan

import (
	"context"
	"fmt"
	"time"

	"github.com/maestroi/hardener/internal/executor"
	"github.com/maestroi/hardener/internal/model"
	"github.com/maestroi/hardener/internal/modules"
)

const packageName = "debsecan"

type Module struct{}

func New() *Module { return &Module{} }

func (m *Module) Metadata() modules.ModuleMetadata {
	return modules.ModuleMetadata{
		ID:               "pkgs-debsecan",
		Name:             "Install debsecan",
		Description:      "Installs debsecan for Debian security vulnerability tracking",
		Category:         "Packages",
		DefaultRisk:      model.RiskLow,
		SupportedDistros: []string{"ubuntu"},
		Tags:             []string{"network-safe", "docker-safe"},
		CanRollback:      true,
		RequiresReboot:   false,
	}
}

func (m *Module) SupportedFindings() []string {
	return []string{"DEB-0811"}
}

func (m *Module) Plan(ctx context.Context, finding *model.Finding, _ *model.Profile, inspect executor.Inspector) (*model.PlannedAction, error) {
	meta := m.Metadata()

	installed, err := inspect.IsPackageInstalled(ctx, packageName)
	if err != nil {
		return nil, fmt.Errorf("pkgs-debsecan: checking %s: %w", packageName, err)
	}
	if installed {
		return &model.PlannedAction{
			FindingID:  finding.ID,
			ModuleID:   meta.ID,
			Applicable: false,
			SkipReason: fmt.Sprintf("package %s is already installed", packageName),
		}, nil
	}

	return &model.PlannedAction{
		FindingID:   finding.ID,
		ModuleID:    meta.ID,
		Title:       "Install debsecan",
		Description: "Install debsecan for Debian security advisory tracking",
		Steps:       []string{fmt.Sprintf("apt-get install -y %s", packageName)},
		Metadata:    map[string]string{"package": packageName},
		Risk:        model.RiskLow,
		CanRollback: true,
		Applicable:  true,
		Tags:        []string{"network-safe", "docker-safe"},
	}, nil
}

func (m *Module) Apply(ctx context.Context, action *model.PlannedAction, exec executor.Executor) (*model.AppliedAction, error) {
	if err := exec.InstallPackage(ctx, packageName); err != nil {
		return nil, fmt.Errorf("pkgs-debsecan: installing %s: %w", packageName, err)
	}
	return &model.AppliedAction{
		PlannedAction: *action,
		AppliedAt:     time.Now(),
		Status:        model.ActionApplied,
	}, nil
}

func (m *Module) Validate(ctx context.Context, _ *model.PlannedAction, inspect executor.Inspector) error {
	ok, err := inspect.IsPackageInstalled(ctx, packageName)
	if err != nil {
		return fmt.Errorf("pkgs-debsecan: checking %s: %w", packageName, err)
	}
	if !ok {
		return fmt.Errorf("pkgs-debsecan: package %s not found after apply", packageName)
	}
	return nil
}

func (m *Module) Rollback(_ context.Context, entry *model.RollbackEntry, _ executor.Executor) error {
	switch entry.Kind {
	case model.RollbackPackage:
		return nil // skip removal to avoid dependency surprises
	default:
		return fmt.Errorf("pkgs-debsecan rollback: unexpected kind %q", entry.Kind)
	}
}
```

- [ ] **Step 4.4: Run tests**

```bash
go test ./internal/modules/packages/debsecan/... -v
```

Expected: all 3 tests pass.

- [ ] **Step 4.5: Commit**

```bash
git add internal/modules/packages/debsecan/
git commit -m "feat(hardener): pkgs-debsecan module — DEB-0811"
```

---

## Task 5: aide module (FINT-4350)

**Files:**
- Create: `internal/modules/packages/aide/module.go`
- Create: `internal/modules/packages/aide/module_test.go`

- [ ] **Step 5.1: Write failing tests**

Create `internal/modules/packages/aide/module_test.go`:

```go
package aide_test

import (
	"context"
	"testing"

	"github.com/maestroi/hardener/internal/model"
	"github.com/maestroi/hardener/internal/modules/packages/aide"
	"github.com/maestroi/hardener/internal/testhelpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPlan_AlreadyInstalled(t *testing.T) {
	m := aide.New()
	inspect := &testhelpers.FakeInspector{
		InstalledPkgs: map[string]bool{"aide": true},
		Files:         map[string][]byte{aide.DBPath: {}},
	}
	action, err := m.Plan(context.Background(), &model.Finding{ID: "FINT-4350"}, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.False(t, action.Applicable)
}

func TestPlan_NotInstalled(t *testing.T) {
	m := aide.New()
	inspect := &testhelpers.FakeInspector{}
	action, err := m.Plan(context.Background(), &model.Finding{ID: "FINT-4350"}, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.True(t, action.Applicable)
}

func TestApplyAndValidate(t *testing.T) {
	m := aide.New()
	exec := &testhelpers.FakeExecutor{
		FakeInspector: testhelpers.FakeInspector{
			Files: map[string][]byte{},
		},
	}
	action := &model.PlannedAction{FindingID: "FINT-4350", ModuleID: "pkgs-aide", Applicable: true}

	applied, err := m.Apply(context.Background(), action, exec)
	require.NoError(t, err)
	assert.Equal(t, model.ActionApplied, applied.Status)
	assert.True(t, exec.PackageInstalled("aide"))

	// Simulate aideinit having created the DB file
	exec.Files[aide.DBPath] = []byte("aide-db")
	err = m.Validate(context.Background(), action, exec)
	assert.NoError(t, err)
}
```

- [ ] **Step 5.2: Run tests to confirm they fail**

```bash
go test ./internal/modules/packages/aide/... -v
```

Expected: compilation error.

- [ ] **Step 5.3: Create module**

Create `internal/modules/packages/aide/module.go`:

```go
package aide

import (
	"context"
	"fmt"
	"time"

	"github.com/maestroi/hardener/internal/executor"
	"github.com/maestroi/hardener/internal/model"
	"github.com/maestroi/hardener/internal/modules"
)

const (
	packageName = "aide"
	DBPath      = "/var/lib/aide/aide.db.new"
)

type Module struct{}

func New() *Module { return &Module{} }

func (m *Module) Metadata() modules.ModuleMetadata {
	return modules.ModuleMetadata{
		ID:               "pkgs-aide",
		Name:             "Install AIDE File Integrity Tool",
		Description:      "Installs aide and initialises its database for file integrity monitoring",
		Category:         "Packages",
		DefaultRisk:      model.RiskLow,
		SupportedDistros: []string{"ubuntu"},
		Tags:             []string{"network-safe", "docker-safe"},
		CanRollback:      true,
		RequiresReboot:   false,
	}
}

func (m *Module) SupportedFindings() []string {
	return []string{"FINT-4350"}
}

func (m *Module) Plan(ctx context.Context, finding *model.Finding, _ *model.Profile, inspect executor.Inspector) (*model.PlannedAction, error) {
	meta := m.Metadata()

	installed, err := inspect.IsPackageInstalled(ctx, packageName)
	if err != nil {
		return nil, fmt.Errorf("pkgs-aide: checking %s: %w", packageName, err)
	}

	dbExists, err := inspect.FileExists(ctx, DBPath)
	if err != nil {
		return nil, fmt.Errorf("pkgs-aide: checking %s: %w", DBPath, err)
	}

	if installed && dbExists {
		return &model.PlannedAction{
			FindingID:  finding.ID,
			ModuleID:   meta.ID,
			Applicable: false,
			SkipReason: fmt.Sprintf("package %s is installed and database %s exists", packageName, DBPath),
		}, nil
	}

	var steps []string
	if !installed {
		steps = append(steps, fmt.Sprintf("apt-get install -y %s", packageName))
	}
	if !dbExists {
		steps = append(steps, "aideinit --yes")
	}

	return &model.PlannedAction{
		FindingID:   finding.ID,
		ModuleID:    meta.ID,
		Title:       "Install AIDE and initialise database",
		Description: "Install file integrity monitoring tool and create its baseline database",
		Steps:       steps,
		Metadata:    map[string]string{"package": packageName, "db_path": DBPath},
		Risk:        model.RiskLow,
		CanRollback: true,
		Applicable:  true,
		Tags:        []string{"network-safe", "docker-safe"},
	}, nil
}

func (m *Module) Apply(ctx context.Context, action *model.PlannedAction, exec executor.Executor) (*model.AppliedAction, error) {
	installed, _ := exec.IsPackageInstalled(ctx, packageName)
	if !installed {
		if err := exec.InstallPackage(ctx, packageName); err != nil {
			return nil, fmt.Errorf("pkgs-aide: installing %s: %w", packageName, err)
		}
	}

	dbExists, _ := exec.FileExists(ctx, DBPath)
	if !dbExists {
		if _, err := exec.Run(ctx, "aideinit", "--yes"); err != nil {
			return nil, fmt.Errorf("pkgs-aide: aideinit: %w", err)
		}
	}

	return &model.AppliedAction{
		PlannedAction: *action,
		AppliedAt:     time.Now(),
		Status:        model.ActionApplied,
	}, nil
}

func (m *Module) Validate(ctx context.Context, _ *model.PlannedAction, inspect executor.Inspector) error {
	ok, err := inspect.IsPackageInstalled(ctx, packageName)
	if err != nil {
		return fmt.Errorf("pkgs-aide: checking package: %w", err)
	}
	if !ok {
		return fmt.Errorf("pkgs-aide: package %s not installed after apply", packageName)
	}

	exists, err := inspect.FileExists(ctx, DBPath)
	if err != nil {
		return fmt.Errorf("pkgs-aide: checking DB: %w", err)
	}
	if !exists {
		return fmt.Errorf("pkgs-aide: database %s not found after apply", DBPath)
	}
	return nil
}

func (m *Module) Rollback(_ context.Context, entry *model.RollbackEntry, _ executor.Executor) error {
	switch entry.Kind {
	case model.RollbackPackage:
		return nil
	default:
		return fmt.Errorf("pkgs-aide rollback: unexpected kind %q", entry.Kind)
	}
}
```

- [ ] **Step 5.4: Run tests**

```bash
go test ./internal/modules/packages/aide/... -v
```

Expected: all 3 tests pass.

- [ ] **Step 5.5: Commit**

```bash
git add internal/modules/packages/aide/
git commit -m "feat(hardener): pkgs-aide module — FINT-4350"
```

---

## Task 6: firewall module (FIRE-4513)

**Files:**
- Create: `internal/modules/network/firewall/module.go`
- Create: `internal/modules/network/firewall/module_test.go`

- [ ] **Step 6.1: Write failing tests**

Create `internal/modules/network/firewall/module_test.go`:

```go
package firewall_test

import (
	"context"
	"testing"

	"github.com/maestroi/hardener/internal/executor"
	"github.com/maestroi/hardener/internal/model"
	"github.com/maestroi/hardener/internal/modules/network/firewall"
	"github.com/maestroi/hardener/internal/testhelpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPlan_AlreadyActive(t *testing.T) {
	m := firewall.New()
	inspect := &testhelpers.FakeInspector{
		InstalledPkgs: map[string]bool{"ufw": true},
		Services:      map[string]executor.ServiceStatus{"ufw": {Name: "ufw", Active: true, Enabled: true}},
	}
	action, err := m.Plan(context.Background(), &model.Finding{ID: "FIRE-4513"}, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.False(t, action.Applicable)
}

func TestPlan_NotPresent(t *testing.T) {
	m := firewall.New()
	inspect := &testhelpers.FakeInspector{}
	action, err := m.Plan(context.Background(), &model.Finding{ID: "FIRE-4513"}, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.True(t, action.Applicable)
	assert.Equal(t, model.RiskMedium, action.Risk)
}

func TestApplyAndValidate(t *testing.T) {
	m := firewall.New()
	exec := &testhelpers.FakeExecutor{}
	action := &model.PlannedAction{FindingID: "FIRE-4513", ModuleID: "network-firewall", Applicable: true}

	applied, err := m.Apply(context.Background(), action, exec)
	require.NoError(t, err)
	assert.Equal(t, model.ActionApplied, applied.Status)
	assert.True(t, exec.PackageInstalled("ufw"))

	err = m.Validate(context.Background(), action, exec)
	assert.NoError(t, err)
}
```

- [ ] **Step 6.2: Run tests to confirm they fail**

```bash
go test ./internal/modules/network/firewall/... -v
```

Expected: compilation error.

- [ ] **Step 6.3: Create module**

Create `internal/modules/network/firewall/module.go`:

```go
package firewall

import (
	"context"
	"fmt"
	"time"

	"github.com/maestroi/hardener/internal/executor"
	"github.com/maestroi/hardener/internal/model"
	"github.com/maestroi/hardener/internal/modules"
)

const (
	packageName = "ufw"
	serviceName = "ufw"
)

type Module struct{}

func New() *Module { return &Module{} }

func (m *Module) Metadata() modules.ModuleMetadata {
	return modules.ModuleMetadata{
		ID:               "network-firewall",
		Name:             "Enable UFW Firewall",
		Description:      "Installs and enables UFW with default-deny incoming policy",
		Category:         "Network",
		DefaultRisk:      model.RiskMedium,
		SupportedDistros: []string{"ubuntu"},
		Tags:             []string{"network-safe"},
		CanRollback:      true,
		RequiresReboot:   false,
	}
}

func (m *Module) SupportedFindings() []string {
	return []string{"FIRE-4513"}
}

func (m *Module) Plan(ctx context.Context, finding *model.Finding, _ *model.Profile, inspect executor.Inspector) (*model.PlannedAction, error) {
	meta := m.Metadata()

	installed, err := inspect.IsPackageInstalled(ctx, packageName)
	if err != nil {
		return nil, fmt.Errorf("network-firewall: checking %s: %w", packageName, err)
	}

	svc, err := inspect.ServiceState(ctx, serviceName)
	if err != nil {
		return nil, fmt.Errorf("network-firewall: checking service %s: %w", serviceName, err)
	}

	if installed && svc.Active && svc.Enabled {
		return &model.PlannedAction{
			FindingID:  finding.ID,
			ModuleID:   meta.ID,
			Applicable: false,
			SkipReason: fmt.Sprintf("ufw is installed and service is active/enabled"),
		}, nil
	}

	var steps []string
	if !installed {
		steps = append(steps, "apt-get install -y ufw")
	}
	steps = append(steps,
		"ufw default deny incoming",
		"ufw default allow outgoing",
		"ufw --force enable",
		"systemctl enable ufw",
	)

	return &model.PlannedAction{
		FindingID:   finding.ID,
		ModuleID:    meta.ID,
		Title:       "Enable UFW firewall",
		Description: "Install UFW and set default-deny incoming policy",
		Steps:       steps,
		Metadata:    map[string]string{"package": packageName, "service": serviceName},
		Risk:        model.RiskMedium,
		Impact:      "Enables firewall with default-deny incoming. Existing allow rules are preserved. SSH access may be affected if port 22 is not allowed.",
		CanRollback: true,
		Applicable:  true,
		Tags:        []string{"network-safe"},
	}, nil
}

func (m *Module) Apply(ctx context.Context, action *model.PlannedAction, exec executor.Executor) (*model.AppliedAction, error) {
	installed, _ := exec.IsPackageInstalled(ctx, packageName)
	if !installed {
		if err := exec.InstallPackage(ctx, packageName); err != nil {
			return nil, fmt.Errorf("network-firewall: installing %s: %w", packageName, err)
		}
	}

	if _, err := exec.Run(ctx, "ufw", "default", "deny", "incoming"); err != nil {
		return nil, fmt.Errorf("network-firewall: ufw default deny: %w", err)
	}
	if _, err := exec.Run(ctx, "ufw", "default", "allow", "outgoing"); err != nil {
		return nil, fmt.Errorf("network-firewall: ufw default allow: %w", err)
	}
	if _, err := exec.Run(ctx, "ufw", "--force", "enable"); err != nil {
		return nil, fmt.Errorf("network-firewall: ufw enable: %w", err)
	}
	if err := exec.EnableService(ctx, serviceName); err != nil {
		return nil, fmt.Errorf("network-firewall: enabling %s: %w", serviceName, err)
	}

	return &model.AppliedAction{
		PlannedAction: *action,
		AppliedAt:     time.Now(),
		Status:        model.ActionApplied,
	}, nil
}

func (m *Module) Validate(ctx context.Context, _ *model.PlannedAction, inspect executor.Inspector) error {
	ok, err := inspect.IsPackageInstalled(ctx, packageName)
	if err != nil {
		return fmt.Errorf("network-firewall: checking package: %w", err)
	}
	if !ok {
		return fmt.Errorf("network-firewall: package %s not installed after apply", packageName)
	}

	svc, err := inspect.ServiceState(ctx, serviceName)
	if err != nil {
		return fmt.Errorf("network-firewall: checking service: %w", err)
	}
	if !svc.Enabled {
		return fmt.Errorf("network-firewall: service %s is not enabled after apply", serviceName)
	}
	return nil
}

func (m *Module) Rollback(_ context.Context, entry *model.RollbackEntry, _ executor.Executor) error {
	switch entry.Kind {
	case model.RollbackPackage:
		return nil
	case model.RollbackService:
		return nil
	default:
		return fmt.Errorf("network-firewall rollback: unexpected kind %q", entry.Kind)
	}
}
```

- [ ] **Step 6.4: Run tests**

```bash
go test ./internal/modules/network/firewall/... -v
```

Expected: all 3 tests pass.

- [ ] **Step 6.5: Commit**

```bash
git add internal/modules/network/firewall/
git commit -m "feat(hardener): network-firewall module — FIRE-4513"
```

---

## Task 7: grubperms module (BOOT-5264)

**Files:**
- Create: `internal/modules/boot/grubperms/module.go`
- Create: `internal/modules/boot/grubperms/module_test.go`

- [ ] **Step 7.1: Write failing tests**

Create `internal/modules/boot/grubperms/module_test.go`:

```go
package grubperms_test

import (
	"context"
	"os"
	"testing"

	"github.com/maestroi/hardener/internal/executor"
	"github.com/maestroi/hardener/internal/model"
	"github.com/maestroi/hardener/internal/modules/boot/grubperms"
	"github.com/maestroi/hardener/internal/testhelpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPlan_AlreadySecure(t *testing.T) {
	m := grubperms.New()
	inspect := &testhelpers.FakeInspector{
		Files: map[string][]byte{grubperms.GrubCfgPath: []byte("set default=0")},
		RunReadOnlyFn: func(name string, args ...string) (executor.CmdOutput, error) {
			return executor.CmdOutput{Stdout: "600\n"}, nil
		},
	}
	action, err := m.Plan(context.Background(), &model.Finding{ID: "BOOT-5264"}, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.False(t, action.Applicable)
}

func TestPlan_InsecurePerms(t *testing.T) {
	m := grubperms.New()
	inspect := &testhelpers.FakeInspector{
		Files: map[string][]byte{grubperms.GrubCfgPath: []byte("set default=0")},
		RunReadOnlyFn: func(name string, args ...string) (executor.CmdOutput, error) {
			return executor.CmdOutput{Stdout: "644\n"}, nil
		},
	}
	action, err := m.Plan(context.Background(), &model.Finding{ID: "BOOT-5264"}, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.True(t, action.Applicable)
}

func TestApplyAndValidate(t *testing.T) {
	m := grubperms.New()
	exec := &testhelpers.FakeExecutor{
		FakeInspector: testhelpers.FakeInspector{
			Files: map[string][]byte{grubperms.GrubCfgPath: []byte("set default=0")},
			RunReadOnlyFn: func(name string, args ...string) (executor.CmdOutput, error) {
				return executor.CmdOutput{Stdout: "600\n"}, nil
			},
		},
	}
	action := &model.PlannedAction{FindingID: "BOOT-5264", ModuleID: "boot-grub-perms", Applicable: true}

	applied, err := m.Apply(context.Background(), action, exec)
	require.NoError(t, err)
	assert.Equal(t, model.ActionApplied, applied.Status)
	assert.Equal(t, os.FileMode(0600), exec.SetFileModeRecords[grubperms.GrubCfgPath])

	err = m.Validate(context.Background(), action, exec)
	assert.NoError(t, err)
}
```

- [ ] **Step 7.2: Run tests to confirm they fail**

```bash
go test ./internal/modules/boot/grubperms/... -v
```

Expected: compilation error.

- [ ] **Step 7.3: Create module**

Create `internal/modules/boot/grubperms/module.go`:

```go
package grubperms

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/maestroi/hardener/internal/executor"
	"github.com/maestroi/hardener/internal/model"
	"github.com/maestroi/hardener/internal/modules"
)

const GrubCfgPath = "/boot/grub/grub.cfg"

type Module struct{}

func New() *Module { return &Module{} }

func (m *Module) Metadata() modules.ModuleMetadata {
	return modules.ModuleMetadata{
		ID:               "boot-grub-perms",
		Name:             "Secure GRUB Configuration Permissions",
		Description:      "Sets /boot/grub/grub.cfg to mode 600 so only root can read the bootloader config",
		Category:         "Boot",
		DefaultRisk:      model.RiskLow,
		SupportedDistros: []string{"ubuntu"},
		Tags:             []string{"network-safe", "docker-safe"},
		CanRollback:      true,
		RequiresReboot:   false,
	}
}

func (m *Module) SupportedFindings() []string {
	return []string{"BOOT-5264"}
}

func (m *Module) Plan(ctx context.Context, finding *model.Finding, _ *model.Profile, inspect executor.Inspector) (*model.PlannedAction, error) {
	meta := m.Metadata()

	exists, err := inspect.FileExists(ctx, GrubCfgPath)
	if err != nil {
		return nil, fmt.Errorf("boot-grub-perms: checking %s: %w", GrubCfgPath, err)
	}
	if !exists {
		return &model.PlannedAction{
			FindingID:  finding.ID,
			ModuleID:   meta.ID,
			Applicable: false,
			SkipReason: fmt.Sprintf("%s does not exist; GRUB may not be installed", GrubCfgPath),
		}, nil
	}

	out, err := inspect.RunReadOnly(ctx, "stat", "-c", "%a", GrubCfgPath)
	if err != nil {
		return nil, fmt.Errorf("boot-grub-perms: stat %s: %w", GrubCfgPath, err)
	}
	mode := strings.TrimSpace(out.Stdout)
	if mode == "600" || mode == "400" {
		return &model.PlannedAction{
			FindingID:  finding.ID,
			ModuleID:   meta.ID,
			Applicable: false,
			SkipReason: fmt.Sprintf("%s already has mode %s", GrubCfgPath, mode),
		}, nil
	}

	return &model.PlannedAction{
		FindingID:   finding.ID,
		ModuleID:    meta.ID,
		Title:       "Set GRUB config permissions to 600",
		Description: fmt.Sprintf("chmod 600 %s (currently %s)", GrubCfgPath, mode),
		Steps:       []string{fmt.Sprintf("chmod 600 %s", GrubCfgPath)},
		Metadata:    map[string]string{"path": GrubCfgPath, "orig_mode": mode},
		Risk:        model.RiskLow,
		CanRollback: true,
		Applicable:  true,
		Tags:        []string{"network-safe", "docker-safe"},
	}, nil
}

func (m *Module) Apply(ctx context.Context, action *model.PlannedAction, exec executor.Executor) (*model.AppliedAction, error) {
	if err := exec.SetFileMode(ctx, GrubCfgPath, 0600); err != nil {
		return nil, fmt.Errorf("boot-grub-perms: chmod %s: %w", GrubCfgPath, err)
	}
	return &model.AppliedAction{
		PlannedAction: *action,
		AppliedAt:     time.Now(),
		Status:        model.ActionApplied,
	}, nil
}

func (m *Module) Validate(ctx context.Context, _ *model.PlannedAction, inspect executor.Inspector) error {
	out, err := inspect.RunReadOnly(ctx, "stat", "-c", "%a", GrubCfgPath)
	if err != nil {
		return fmt.Errorf("boot-grub-perms: stat %s: %w", GrubCfgPath, err)
	}
	mode := strings.TrimSpace(out.Stdout)
	if mode != "600" && mode != "400" {
		return fmt.Errorf("boot-grub-perms: %s has mode %s, want 600", GrubCfgPath, mode)
	}
	return nil
}

func (m *Module) Rollback(ctx context.Context, entry *model.RollbackEntry, exec executor.Executor) error {
	switch entry.Kind {
	case model.RollbackFile:
		if err := exec.SetFileMode(ctx, entry.Path, entry.OrigMode); err != nil {
			return fmt.Errorf("boot-grub-perms: restoring mode on %s: %w", entry.Path, err)
		}
		return nil
	default:
		return fmt.Errorf("boot-grub-perms rollback: unexpected kind %q", entry.Kind)
	}
}
```

- [ ] **Step 7.4: Run tests**

```bash
go test ./internal/modules/boot/grubperms/... -v
```

Expected: all 3 tests pass.

- [ ] **Step 7.5: Commit**

```bash
git add internal/modules/boot/grubperms/
git commit -m "feat(hardener): boot-grub-perms module — BOOT-5264"
```

---

## Task 8: usbstorage module (USB-1000, HRDN-7230)

**Files:**
- Create: `internal/modules/kernel/usbstorage/module.go`
- Create: `internal/modules/kernel/usbstorage/module_test.go`

- [ ] **Step 8.1: Write failing tests**

Create `internal/modules/kernel/usbstorage/module_test.go`:

```go
package usbstorage_test

import (
	"context"
	"testing"

	"github.com/maestroi/hardener/internal/model"
	"github.com/maestroi/hardener/internal/modules/kernel/usbstorage"
	"github.com/maestroi/hardener/internal/testhelpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPlan_AlreadyBlacklisted(t *testing.T) {
	m := usbstorage.New()
	inspect := &testhelpers.FakeInspector{
		Files: map[string][]byte{usbstorage.ConfPath: []byte(usbstorage.ConfContent)},
	}
	action, err := m.Plan(context.Background(), &model.Finding{ID: "USB-1000"}, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.False(t, action.Applicable)
}

func TestPlan_NotPresent(t *testing.T) {
	m := usbstorage.New()
	inspect := &testhelpers.FakeInspector{}
	action, err := m.Plan(context.Background(), &model.Finding{ID: "HRDN-7230"}, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.True(t, action.Applicable)
}

func TestApplyAndValidate(t *testing.T) {
	m := usbstorage.New()
	exec := &testhelpers.FakeExecutor{}
	action := &model.PlannedAction{FindingID: "USB-1000", ModuleID: "kernel-usb-storage", Applicable: true}

	applied, err := m.Apply(context.Background(), action, exec)
	require.NoError(t, err)
	assert.Equal(t, model.ActionApplied, applied.Status)
	assert.True(t, exec.FileContains(usbstorage.ConfPath, "blacklist usb-storage"))

	err = m.Validate(context.Background(), action, exec)
	assert.NoError(t, err)
}
```

- [ ] **Step 8.2: Run tests to confirm they fail**

```bash
go test ./internal/modules/kernel/usbstorage/... -v
```

Expected: compilation error.

- [ ] **Step 8.3: Create module**

Create `internal/modules/kernel/usbstorage/module.go`:

```go
package usbstorage

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
	ConfPath = "/etc/modprobe.d/usb-storage.conf"

	ConfContent = `# Managed by hardener — do not edit manually.
install usb-storage /bin/true
blacklist usb-storage
`
)

type Module struct{}

func New() *Module { return &Module{} }

func (m *Module) Metadata() modules.ModuleMetadata {
	return modules.ModuleMetadata{
		ID:               "kernel-usb-storage",
		Name:             "Disable USB Storage",
		Description:      "Blacklists the usb-storage kernel module to prevent USB mass storage devices from mounting",
		Category:         "Kernel",
		DefaultRisk:      model.RiskMedium,
		SupportedDistros: []string{"ubuntu"},
		Tags:             []string{"network-safe"},
		CanRollback:      true,
		RequiresReboot:   true,
	}
}

func (m *Module) SupportedFindings() []string {
	return []string{"USB-1000", "HRDN-7230"}
}

func (m *Module) Plan(ctx context.Context, finding *model.Finding, _ *model.Profile, inspect executor.Inspector) (*model.PlannedAction, error) {
	meta := m.Metadata()

	content, err := inspect.ReadFile(ctx, ConfPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("kernel-usb-storage: reading %s: %w", ConfPath, err)
	}

	if err == nil && strings.Contains(string(content), "blacklist usb-storage") {
		return &model.PlannedAction{
			FindingID:  finding.ID,
			ModuleID:   meta.ID,
			Applicable: false,
			SkipReason: fmt.Sprintf("%s already blacklists usb-storage", ConfPath),
		}, nil
	}

	return &model.PlannedAction{
		FindingID:      finding.ID,
		ModuleID:       meta.ID,
		Title:          "Blacklist USB storage module",
		Description:    fmt.Sprintf("Write %s to disable USB mass storage mounting", ConfPath),
		Steps:          []string{fmt.Sprintf("write %s", ConfPath)},
		Metadata:       map[string]string{"target_file": ConfPath},
		Risk:           model.RiskMedium,
		Impact:         "USB mass storage devices will not mount after reboot. USB input devices (keyboard, mouse) are unaffected.",
		RequiresReboot: true,
		CanRollback:    true,
		Applicable:     true,
		Tags:           []string{"network-safe"},
	}, nil
}

func (m *Module) Apply(ctx context.Context, action *model.PlannedAction, exec executor.Executor) (*model.AppliedAction, error) {
	if err := exec.WriteFile(ctx, ConfPath, []byte(ConfContent), 0644); err != nil {
		return nil, fmt.Errorf("kernel-usb-storage: writing %s: %w", ConfPath, err)
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
		return fmt.Errorf("kernel-usb-storage: reading %s: %w", ConfPath, err)
	}
	if !strings.Contains(string(content), "blacklist usb-storage") {
		return fmt.Errorf("kernel-usb-storage: blacklist entry missing from %s", ConfPath)
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
			return fmt.Errorf("kernel-usb-storage: reading backup %s: %w", entry.BackupPath, err)
		}
		return exec.WriteFile(ctx, entry.Path, backup, entry.OrigMode)
	default:
		return fmt.Errorf("kernel-usb-storage rollback: unexpected kind %q", entry.Kind)
	}
}
```

- [ ] **Step 8.4: Run tests**

```bash
go test ./internal/modules/kernel/usbstorage/... -v
```

Expected: all 3 tests pass.

- [ ] **Step 8.5: Commit**

```bash
git add internal/modules/kernel/usbstorage/
git commit -m "feat(hardener): kernel-usb-storage module — USB-1000, HRDN-7230"
```

---

## Task 9: protocols module (NETW-3200)

**Files:**
- Create: `internal/modules/kernel/protocols/module.go`
- Create: `internal/modules/kernel/protocols/module_test.go`

- [ ] **Step 9.1: Write failing tests**

Create `internal/modules/kernel/protocols/module_test.go`:

```go
package protocols_test

import (
	"context"
	"testing"

	"github.com/maestroi/hardener/internal/model"
	"github.com/maestroi/hardener/internal/modules/kernel/protocols"
	"github.com/maestroi/hardener/internal/testhelpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPlan_AlreadyDisabled(t *testing.T) {
	m := protocols.New()
	inspect := &testhelpers.FakeInspector{
		Files: map[string][]byte{protocols.ConfPath: []byte(protocols.ConfContent)},
	}
	action, err := m.Plan(context.Background(), &model.Finding{ID: "NETW-3200"}, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.False(t, action.Applicable)
}

func TestPlan_NotPresent(t *testing.T) {
	m := protocols.New()
	inspect := &testhelpers.FakeInspector{}
	action, err := m.Plan(context.Background(), &model.Finding{ID: "NETW-3200"}, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.True(t, action.Applicable)
}

func TestApplyAndValidate(t *testing.T) {
	m := protocols.New()
	exec := &testhelpers.FakeExecutor{}
	action := &model.PlannedAction{FindingID: "NETW-3200", ModuleID: "kernel-protocols", Applicable: true}

	applied, err := m.Apply(context.Background(), action, exec)
	require.NoError(t, err)
	assert.Equal(t, model.ActionApplied, applied.Status)
	assert.True(t, exec.FileContains(protocols.ConfPath, "install dccp /bin/true"))
	assert.True(t, exec.FileContains(protocols.ConfPath, "install tipc /bin/true"))

	err = m.Validate(context.Background(), action, exec)
	assert.NoError(t, err)
}
```

- [ ] **Step 9.2: Run tests to confirm they fail**

```bash
go test ./internal/modules/kernel/protocols/... -v
```

Expected: compilation error.

- [ ] **Step 9.3: Create module**

Create `internal/modules/kernel/protocols/module.go`:

```go
package protocols

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
	ConfPath = "/etc/modprobe.d/disable-protocols.conf"

	ConfContent = `# Managed by hardener — do not edit manually.
install dccp /bin/true
install sctp /bin/true
install rds /bin/true
install tipc /bin/true
`
)

type Module struct{}

func New() *Module { return &Module{} }

func (m *Module) Metadata() modules.ModuleMetadata {
	return modules.ModuleMetadata{
		ID:               "kernel-protocols",
		Name:             "Disable Unused Network Protocols",
		Description:      "Blacklists dccp, sctp, rds, and tipc kernel modules to reduce network attack surface",
		Category:         "Kernel",
		DefaultRisk:      model.RiskMedium,
		SupportedDistros: []string{"ubuntu"},
		Tags:             []string{"network-safe"},
		CanRollback:      true,
		RequiresReboot:   true,
	}
}

func (m *Module) SupportedFindings() []string {
	return []string{"NETW-3200"}
}

func (m *Module) Plan(ctx context.Context, finding *model.Finding, _ *model.Profile, inspect executor.Inspector) (*model.PlannedAction, error) {
	meta := m.Metadata()

	content, err := inspect.ReadFile(ctx, ConfPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("kernel-protocols: reading %s: %w", ConfPath, err)
	}

	if err == nil &&
		strings.Contains(string(content), "install dccp") &&
		strings.Contains(string(content), "install sctp") &&
		strings.Contains(string(content), "install rds") &&
		strings.Contains(string(content), "install tipc") {
		return &model.PlannedAction{
			FindingID:  finding.ID,
			ModuleID:   meta.ID,
			Applicable: false,
			SkipReason: fmt.Sprintf("%s already disables dccp/sctp/rds/tipc", ConfPath),
		}, nil
	}

	return &model.PlannedAction{
		FindingID:      finding.ID,
		ModuleID:       meta.ID,
		Title:          "Disable unused network protocols",
		Description:    fmt.Sprintf("Write %s to disable dccp, sctp, rds, tipc modules", ConfPath),
		Steps:          []string{fmt.Sprintf("write %s", ConfPath)},
		Metadata:       map[string]string{"target_file": ConfPath},
		Risk:           model.RiskMedium,
		Impact:         "Prevents loading of dccp/sctp/rds/tipc kernel modules. Takes effect after reboot or modprobe removal.",
		RequiresReboot: true,
		CanRollback:    true,
		Applicable:     true,
		Tags:           []string{"network-safe"},
	}, nil
}

func (m *Module) Apply(ctx context.Context, action *model.PlannedAction, exec executor.Executor) (*model.AppliedAction, error) {
	if err := exec.WriteFile(ctx, ConfPath, []byte(ConfContent), 0644); err != nil {
		return nil, fmt.Errorf("kernel-protocols: writing %s: %w", ConfPath, err)
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
		return fmt.Errorf("kernel-protocols: reading %s: %w", ConfPath, err)
	}
	for _, proto := range []string{"dccp", "sctp", "rds", "tipc"} {
		if !strings.Contains(string(content), fmt.Sprintf("install %s", proto)) {
			return fmt.Errorf("kernel-protocols: %s missing from %s", proto, ConfPath)
		}
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
			return fmt.Errorf("kernel-protocols: reading backup %s: %w", entry.BackupPath, err)
		}
		return exec.WriteFile(ctx, entry.Path, backup, entry.OrigMode)
	default:
		return fmt.Errorf("kernel-protocols rollback: unexpected kind %q", entry.Kind)
	}
}
```

- [ ] **Step 9.4: Run tests**

```bash
go test ./internal/modules/kernel/protocols/... -v
```

Expected: all 3 tests pass.

- [ ] **Step 9.5: Commit**

```bash
git add internal/modules/kernel/protocols/
git commit -m "feat(hardener): kernel-protocols module — NETW-3200"
```

---

## Task 10: Wire up registry and clean advisory/manual

**Files:**
- Modify: `internal/registry/init.go`
- Modify: `internal/modules/advisory/manual/module.go`

- [ ] **Step 10.1: Register all 8 new modules in registry**

In `internal/registry/init.go`, add the new imports and `Register` calls. The final imports block should include:

```go
import (
	manualmod "github.com/maestroi/hardener/internal/modules/advisory/manual"
	acctmod "github.com/maestroi/hardener/internal/modules/accounting/acct"
	auditdmod "github.com/maestroi/hardener/internal/modules/accounting/auditd"
	pamfaillockmod "github.com/maestroi/hardener/internal/modules/auth/pamfaillock"
	pamhistmod "github.com/maestroi/hardener/internal/modules/auth/pamhistory"
	passagingmod "github.com/maestroi/hardener/internal/modules/auth/passwordaging"
	pwqualmod "github.com/maestroi/hardener/internal/modules/auth/pwquality"
	sudoersmod "github.com/maestroi/hardener/internal/modules/auth/sudoers"
	umaskmod "github.com/maestroi/hardener/internal/modules/auth/umask"
	bannermod "github.com/maestroi/hardener/internal/modules/banner"
	grubpermsmod "github.com/maestroi/hardener/internal/modules/boot/grubperms"
	coredumpmod "github.com/maestroi/hardener/internal/modules/kernel/coredump"
	protocolsmod "github.com/maestroi/hardener/internal/modules/kernel/protocols"
	sysctlmod "github.com/maestroi/hardener/internal/modules/kernel/sysctl"
	usbstoragemod "github.com/maestroi/hardener/internal/modules/kernel/usbstorage"
	logrotmod "github.com/maestroi/hardener/internal/modules/logging/logrotate"
	firewallmod "github.com/maestroi/hardener/internal/modules/network/firewall"
	aidemod "github.com/maestroi/hardener/internal/modules/packages/aide"
	aptconfigmod "github.com/maestroi/hardener/internal/modules/packages/aptconfig"
	debpurgemod "github.com/maestroi/hardener/internal/modules/packages/debpurge"
	debsecanmod "github.com/maestroi/hardener/internal/modules/packages/debsecan"
	debsumsmod "github.com/maestroi/hardener/internal/modules/packages/debsums"
	unattmod "github.com/maestroi/hardener/internal/modules/packages/unattended"
	sshmod "github.com/maestroi/hardener/internal/modules/ssh"
)
```

Replace the `Default()` function body with:

```go
func Default() *Registry {
	r := New()
	r.Register(sshmod.New())
	r.Register(pwqualmod.New())
	r.Register(passagingmod.New())
	r.Register(umaskmod.New())
	r.Register(pamhistmod.New())
	r.Register(pamfaillockmod.New())
	r.Register(sudoersmod.New())
	r.Register(debsumsmod.New())
	r.Register(unattmod.New())
	r.Register(bannermod.New())
	r.Register(logrotmod.New())
	r.Register(acctmod.New())
	r.Register(auditdmod.New())
	r.Register(sysctlmod.New())
	r.Register(coredumpmod.New())
	// Batch 1: safe modules
	r.Register(aptconfigmod.New())
	r.Register(debpurgemod.New())
	r.Register(debsecanmod.New())
	r.Register(aidemod.New())
	r.Register(firewallmod.New())
	r.Register(grubpermsmod.New())
	r.Register(usbstoragemod.New())
	r.Register(protocolsmod.New())
	// Advisory catch-all — must be last
	r.Register(manualmod.New())
	return r
}
```

- [ ] **Step 10.2: Remove batch 1 finding IDs from advisory/manual**

In `internal/modules/advisory/manual/module.go`, update `supportedFindings` to remove the 10 finding IDs now handled by batch 1 modules. The new list is:

```go
var supportedFindings = []string{
	// Batch 2 (medium) — not yet implemented
	"HRDN-7222",
	"NAME-4028",
	"LOGG-2190",
	// Batch 3 (dangerous) — not yet implemented
	"BOOT-5122",
	"KRNL-5830",
	"FILE-6310",
	"FILE-7524",
}
```

- [ ] **Step 10.3: Run full test suite**

```bash
go test ./... -v 2>&1 | tail -40
```

Expected: all tests pass. If registry tests fail, confirm the new modules compile and are registered correctly.

- [ ] **Step 10.4: Build the binary to confirm it compiles**

```bash
go build ./...
```

Expected: no errors.

- [ ] **Step 10.5: Commit**

```bash
git add internal/registry/init.go internal/modules/advisory/manual/module.go
git commit -m "feat(hardener): register batch 1 modules; clean advisory/manual for 10 findings"
```
