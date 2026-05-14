# Hardener Group 1 Modules Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement six hardening modules (PKGS-7394, PKGS-7370, BANN-7126/7130, LOGG-2154, ACCT-9622, ACCT-9626), a shared test-helpers package, and wire everything into the registry so all six findings move from "no module registered" to "planned" in dry-run output.

**Architecture:** Each module follows the stateless Module interface pattern established by the SSH module: `Plan` (read-only Inspector) → `Apply` (mutating Executor) → `Validate` (read-only Inspector) → `Rollback` (mutating Executor, receives pre-built RollbackEntry). A shared `internal/testhelpers` package replaces the inline fakes from the SSH test file, giving every new module test a richer FakeExecutor that tracks package installs and service lifecycle calls.

**Tech Stack:** Go 1.22, `github.com/maestroi/hardener` module, `github.com/stretchr/testify`, existing `executor.Inspector`/`executor.Executor` interfaces.

---

## File Map

| File | Action | Purpose |
|------|--------|---------|
| `internal/testhelpers/fakes.go` | Create | Shared FakeInspector + FakeExecutor for all module tests |
| `internal/testhelpers/fakes_test.go` | Create | Self-test that the fakes satisfy the interfaces |
| `internal/modules/packages/debsums/module.go` | Create | PKGS-7394: install debsums |
| `internal/modules/packages/debsums/module_test.go` | Create | Tests for debsums module |
| `internal/modules/packages/unattended/module.go` | Create | PKGS-7370: install + enable unattended-upgrades |
| `internal/modules/packages/unattended/module_test.go` | Create | Tests for unattended-upgrades module |
| `internal/modules/banner/module.go` | Create | BANN-7126+7130: write legal banners to /etc/issue and /etc/issue.net |
| `internal/modules/banner/module_test.go` | Create | Tests for banner module |
| `testdata/banner/issue_empty` | Create | Empty /etc/issue fixture |
| `testdata/banner/issue_set` | Create | /etc/issue fixture with banner already set |
| `internal/modules/logging/logrotate/module.go` | Create | LOGG-2154: ensure logrotate compress is set |
| `internal/modules/logging/logrotate/module_test.go` | Create | Tests for logrotate module |
| `testdata/logrotate/logrotate.conf_default` | Create | logrotate.conf without compress |
| `testdata/logrotate/logrotate.conf_compressed` | Create | logrotate.conf with compress already set |
| `internal/modules/accounting/acct/module.go` | Create | ACCT-9622: install + enable acct |
| `internal/modules/accounting/acct/module_test.go` | Create | Tests for acct module |
| `internal/modules/accounting/auditd/module.go` | Create | ACCT-9626: install + enable auditd |
| `internal/modules/accounting/auditd/module_test.go` | Create | Tests for auditd module |
| `internal/registry/init.go` | Modify | Register all six new modules |

---

## Task 0: Shared testhelpers package

**Files:**
- Create: `internal/testhelpers/fakes.go`
- Create: `internal/testhelpers/fakes_test.go`

- [ ] **Step 1: Write the fakes**

Create `internal/testhelpers/fakes.go`:

```go
package testhelpers

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/maestroi/hardener/internal/executor"
)

// FakeInspector returns controlled read-only system state for tests.
// All fields are exported so tests can populate them directly.
type FakeInspector struct {
	Files         map[string][]byte
	Services      map[string]executor.ServiceStatus
	InstalledPkgs map[string]bool
	SysctlValues  map[string]string
}

func (f *FakeInspector) ReadFile(_ context.Context, path string) ([]byte, error) {
	if data, ok := f.Files[path]; ok {
		return data, nil
	}
	return nil, os.ErrNotExist
}

func (f *FakeInspector) FileExists(_ context.Context, path string) (bool, error) {
	_, ok := f.Files[path]
	return ok, nil
}

func (f *FakeInspector) GetSysctl(_ context.Context, key string) (string, error) {
	if v, ok := f.SysctlValues[key]; ok {
		return v, nil
	}
	return "", nil
}

func (f *FakeInspector) ServiceState(_ context.Context, name string) (executor.ServiceStatus, error) {
	if s, ok := f.Services[name]; ok {
		return s, nil
	}
	return executor.ServiceStatus{Name: name}, nil
}

func (f *FakeInspector) IsPackageInstalled(_ context.Context, name string) (bool, error) {
	return f.InstalledPkgs[name], nil
}

func (f *FakeInspector) RunReadOnly(_ context.Context, _ string, _ ...string) (executor.CmdOutput, error) {
	return executor.CmdOutput{}, nil
}

// FakeExecutor embeds FakeInspector and records all mutations.
// Tests inspect the Recorded* slices after Apply/Rollback calls.
type FakeExecutor struct {
	FakeInspector

	// Recorded mutations — inspected by tests.
	WrittenFiles      map[string][]byte
	InstalledPackages []string
	EnabledServices   []string
	DisabledServices  []string
	StartedServices   []string
	StoppedServices   []string
	RestartedServices []string

	// IsDryRunFlag controls IsDryRun().
	IsDryRunFlag bool

	// RunFn optionally overrides Run(). If nil, Run always returns empty CmdOutput, nil.
	RunFn func(name string, args ...string) (executor.CmdOutput, error)
}

// ReadFile checks WrittenFiles first (so Apply-then-Validate round-trips work),
// then falls back to FakeInspector.
func (f *FakeExecutor) ReadFile(ctx context.Context, path string) ([]byte, error) {
	if f.WrittenFiles != nil {
		if data, ok := f.WrittenFiles[path]; ok {
			return data, nil
		}
	}
	return f.FakeInspector.ReadFile(ctx, path)
}

func (f *FakeExecutor) FileExists(ctx context.Context, path string) (bool, error) {
	if f.WrittenFiles != nil {
		if _, ok := f.WrittenFiles[path]; ok {
			return true, nil
		}
	}
	return f.FakeInspector.FileExists(ctx, path)
}

func (f *FakeExecutor) WriteFile(_ context.Context, path string, content []byte, _ os.FileMode) error {
	if f.WrittenFiles == nil {
		f.WrittenFiles = make(map[string][]byte)
	}
	f.WrittenFiles[path] = content
	if f.Files == nil {
		f.Files = make(map[string][]byte)
	}
	f.Files[path] = content
	return nil
}

func (f *FakeExecutor) AppendFile(ctx context.Context, path string, content []byte) error {
	existing, _ := f.ReadFile(ctx, path)
	return f.WriteFile(ctx, path, append(existing, content...), 0)
}

func (f *FakeExecutor) SetFileMode(_ context.Context, _ string, _ os.FileMode) error { return nil }
func (f *FakeExecutor) SetOwner(_ context.Context, _ string, _, _ int) error         { return nil }
func (f *FakeExecutor) SetSysctl(_ context.Context, _, _ string) error               { return nil }

func (f *FakeExecutor) EnableService(_ context.Context, name string) error {
	f.EnabledServices = append(f.EnabledServices, name)
	if f.Services == nil {
		f.Services = make(map[string]executor.ServiceStatus)
	}
	s := f.Services[name]
	s.Name = name
	s.Enabled = true
	f.Services[name] = s
	return nil
}

func (f *FakeExecutor) DisableService(_ context.Context, name string) error {
	f.DisabledServices = append(f.DisabledServices, name)
	return nil
}

func (f *FakeExecutor) StartService(_ context.Context, name string) error {
	f.StartedServices = append(f.StartedServices, name)
	if f.Services == nil {
		f.Services = make(map[string]executor.ServiceStatus)
	}
	s := f.Services[name]
	s.Name = name
	s.Active = true
	f.Services[name] = s
	return nil
}

func (f *FakeExecutor) StopService(_ context.Context, name string) error {
	f.StoppedServices = append(f.StoppedServices, name)
	return nil
}

func (f *FakeExecutor) RestartService(_ context.Context, name string) error {
	f.RestartedServices = append(f.RestartedServices, name)
	return nil
}

func (f *FakeExecutor) InstallPackage(_ context.Context, name string) error {
	f.InstalledPackages = append(f.InstalledPackages, name)
	if f.InstalledPkgs == nil {
		f.InstalledPkgs = make(map[string]bool)
	}
	f.InstalledPkgs[name] = true
	return nil
}

func (f *FakeExecutor) Run(_ context.Context, name string, args ...string) (executor.CmdOutput, error) {
	if f.RunFn != nil {
		return f.RunFn(name, args...)
	}
	return executor.CmdOutput{}, nil
}

func (f *FakeExecutor) IsDryRun() bool { return f.IsDryRunFlag }

// ContainsService returns true if name appears in slice.
func ContainsService(slice []string, name string) bool {
	for _, s := range slice {
		if s == name {
			return true
		}
	}
	return false
}

// FileContains returns true if the written file at path contains substr.
func (f *FakeExecutor) FileContains(path, substr string) bool {
	data, ok := f.WrittenFiles[path]
	if !ok {
		return false
	}
	return strings.Contains(string(data), substr)
}

// HasWritten returns true if path was written by this executor.
func (f *FakeExecutor) HasWritten(path string) bool {
	_, ok := f.WrittenFiles[path]
	return ok
}

// PackageInstalled is a helper for asserting InstallPackage was called.
func (f *FakeExecutor) PackageInstalled(name string) bool {
	for _, p := range f.InstalledPackages {
		if p == name {
			return true
		}
	}
	return false
}

var _ = fmt.Sprintf // suppress unused import if fmt is only used by helpers
```

- [ ] **Step 2: Write the interface-compliance test**

Create `internal/testhelpers/fakes_test.go`:

```go
package testhelpers_test

import (
	"context"
	"testing"

	"github.com/maestroi/hardener/internal/executor"
	"github.com/maestroi/hardener/internal/testhelpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Compile-time checks that both fakes implement the relevant interfaces.
var _ executor.Inspector = (*testhelpers.FakeInspector)(nil)
var _ executor.Executor = (*testhelpers.FakeExecutor)(nil)

func TestFakeExecutor_TracksInstallPackage(t *testing.T) {
	exec := &testhelpers.FakeExecutor{
		FakeInspector: testhelpers.FakeInspector{
			InstalledPkgs: map[string]bool{},
		},
	}

	require.NoError(t, exec.InstallPackage(context.Background(), "debsums"))
	assert.True(t, exec.PackageInstalled("debsums"))

	ok, err := exec.IsPackageInstalled(context.Background(), "debsums")
	require.NoError(t, err)
	assert.True(t, ok, "InstalledPkgs must be updated after InstallPackage")
}

func TestFakeExecutor_TracksServiceLifecycle(t *testing.T) {
	exec := &testhelpers.FakeExecutor{}

	require.NoError(t, exec.EnableService(context.Background(), "auditd"))
	require.NoError(t, exec.StartService(context.Background(), "auditd"))

	assert.True(t, testhelpers.ContainsService(exec.EnabledServices, "auditd"))
	assert.True(t, testhelpers.ContainsService(exec.StartedServices, "auditd"))

	state, err := exec.ServiceState(context.Background(), "auditd")
	require.NoError(t, err)
	assert.True(t, state.Active)
	assert.True(t, state.Enabled)
}

func TestFakeExecutor_WriteReadRoundTrip(t *testing.T) {
	exec := &testhelpers.FakeExecutor{}
	require.NoError(t, exec.WriteFile(context.Background(), "/etc/issue", []byte("banner text"), 0644))
	assert.True(t, exec.FileContains("/etc/issue", "banner"))
	assert.True(t, exec.HasWritten("/etc/issue"))
}
```

- [ ] **Step 3: Run tests**

```bash
cd /home/maestro/Documents/projects/lynis-autofix
go test ./internal/testhelpers/... -v
```

Expected: PASS — both interface assertions and three behavioral tests.

- [ ] **Step 4: Commit**

```bash
git add internal/testhelpers/
git commit -m "feat: add shared FakeInspector/FakeExecutor testhelpers package"
```

---

## Task 1: PKGS-7394 — debsums module

Lynis finding: "Install debsums utility to periodically verify installed packages."
Fix: install the `debsums` package. No service to manage.

**Files:**
- Create: `internal/modules/packages/debsums/module.go`
- Create: `internal/modules/packages/debsums/module_test.go`

- [ ] **Step 1: Write the failing tests**

Create `internal/modules/packages/debsums/module_test.go`:

```go
package debsums_test

import (
	"context"
	"testing"

	"github.com/maestroi/hardener/internal/model"
	debsumsmod "github.com/maestroi/hardener/internal/modules/packages/debsums"
	"github.com/maestroi/hardener/internal/testhelpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDebsums_Metadata(t *testing.T) {
	m := debsumsmod.New()
	meta := m.Metadata()
	assert.Equal(t, "pkgs-debsums", meta.ID)
	assert.Contains(t, meta.SupportedDistros, "ubuntu")
	assert.True(t, meta.CanRollback)
	assert.False(t, meta.RequiresReboot)
}

func TestDebsums_SupportedFindings(t *testing.T) {
	assert.Contains(t, debsumsmod.New().SupportedFindings(), "PKGS-7394")
}

func TestDebsums_Plan_AlreadyInstalled_NotApplicable(t *testing.T) {
	inspect := &testhelpers.FakeInspector{
		InstalledPkgs: map[string]bool{"debsums": true},
	}
	m := debsumsmod.New()
	action, err := m.Plan(context.Background(), &model.Finding{ID: "PKGS-7394"}, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.False(t, action.Applicable)
	assert.NotEmpty(t, action.SkipReason)
}

func TestDebsums_Plan_NotInstalled_Applicable(t *testing.T) {
	inspect := &testhelpers.FakeInspector{
		InstalledPkgs: map[string]bool{},
	}
	m := debsumsmod.New()
	action, err := m.Plan(context.Background(), &model.Finding{ID: "PKGS-7394"}, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.True(t, action.Applicable)
	assert.NotEmpty(t, action.Steps)
}

func TestDebsums_Apply_InstallsPackage(t *testing.T) {
	exec := &testhelpers.FakeExecutor{
		FakeInspector: testhelpers.FakeInspector{
			InstalledPkgs: map[string]bool{},
		},
	}
	m := debsumsmod.New()
	action := &model.PlannedAction{FindingID: "PKGS-7394", ModuleID: "pkgs-debsums"}

	applied, err := m.Apply(context.Background(), action, exec)
	require.NoError(t, err)
	assert.Equal(t, model.ActionApplied, applied.Status)
	assert.True(t, exec.PackageInstalled("debsums"))
}

func TestDebsums_Validate_PackagePresent_NoError(t *testing.T) {
	inspect := &testhelpers.FakeInspector{
		InstalledPkgs: map[string]bool{"debsums": true},
	}
	m := debsumsmod.New()
	err := m.Validate(context.Background(), &model.PlannedAction{FindingID: "PKGS-7394"}, inspect)
	assert.NoError(t, err)
}

func TestDebsums_Validate_PackageMissing_Error(t *testing.T) {
	inspect := &testhelpers.FakeInspector{
		InstalledPkgs: map[string]bool{},
	}
	m := debsumsmod.New()
	err := m.Validate(context.Background(), &model.PlannedAction{FindingID: "PKGS-7394"}, inspect)
	assert.Error(t, err)
}

func TestDebsums_Rollback_PackageNotPreInstalled_IsNoOp(t *testing.T) {
	exec := &testhelpers.FakeExecutor{}
	m := debsumsmod.New()
	entry := &model.RollbackEntry{
		Kind:        model.RollbackPackage,
		PackageName: "debsums",
		WasInstalled: false,
	}
	// MVP: package rollback is a no-op to avoid dependency surprises.
	err := m.Rollback(context.Background(), entry, exec)
	assert.NoError(t, err)
}
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
go test ./internal/modules/packages/debsums/... -v
```

Expected: FAIL — package does not exist yet.

- [ ] **Step 3: Write the module**

Create `internal/modules/packages/debsums/module.go`:

```go
package debsums

import (
	"context"
	"fmt"
	"time"

	"github.com/maestroi/hardener/internal/executor"
	"github.com/maestroi/hardener/internal/model"
	"github.com/maestroi/hardener/internal/modules"
)

const packageName = "debsums"

// Module remediates PKGS-7394 by installing the debsums package.
type Module struct{}

func New() *Module { return &Module{} }

func (m *Module) Metadata() modules.ModuleMetadata {
	return modules.ModuleMetadata{
		ID:               "pkgs-debsums",
		Name:             "Install debsums",
		Description:      "Installs debsums to enable periodic integrity verification of installed packages",
		Category:         "Software",
		DefaultRisk:      model.RiskLow,
		SupportedDistros: []string{"ubuntu"},
		Tags:             []string{"network-safe", "docker-safe"},
		CanRollback:      true,
		RequiresReboot:   false,
	}
}

func (m *Module) SupportedFindings() []string {
	return []string{"PKGS-7394"}
}

func (m *Module) Plan(ctx context.Context, finding *model.Finding, _ *model.Profile, inspect executor.Inspector) (*model.PlannedAction, error) {
	meta := m.Metadata()
	installed, err := inspect.IsPackageInstalled(ctx, packageName)
	if err != nil {
		return nil, fmt.Errorf("checking %s: %w", packageName, err)
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
		Title:       "Install debsums",
		Description: "Install debsums for dpkg package integrity verification",
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
		return nil, fmt.Errorf("installing %s: %w", packageName, err)
	}
	return &model.AppliedAction{
		PlannedAction: *action,
		AppliedAt:     time.Now(),
		Status:        model.ActionApplied,
	}, nil
}

func (m *Module) Validate(ctx context.Context, action *model.PlannedAction, inspect executor.Inspector) error {
	ok, err := inspect.IsPackageInstalled(ctx, packageName)
	if err != nil {
		return fmt.Errorf("checking %s after apply: %w", packageName, err)
	}
	if !ok {
		return fmt.Errorf("package %s not found after install", packageName)
	}
	return nil
}

func (m *Module) Rollback(_ context.Context, entry *model.RollbackEntry, _ executor.Executor) error {
	if entry.Kind != model.RollbackPackage {
		return fmt.Errorf("pkgs-debsums rollback: unexpected kind %q", entry.Kind)
	}
	// MVP: skip removal to avoid removing a package with shared dependants.
	// WasInstalled=false means we installed it; WasInstalled=true means it was pre-existing.
	return nil
}
```

- [ ] **Step 4: Run tests**

```bash
go test ./internal/modules/packages/debsums/... -v
```

Expected: PASS — 7 tests.

- [ ] **Step 5: Commit**

```bash
git add internal/modules/packages/debsums/
git commit -m "feat: add PKGS-7394 debsums module"
```

---

## Task 2: PKGS-7370 — unattended-upgrades module

Lynis finding: "Enable unattended package upgrades."
Fix: install `unattended-upgrades` and enable/start the `unattended-upgrades` service.

**Files:**
- Create: `internal/modules/packages/unattended/module.go`
- Create: `internal/modules/packages/unattended/module_test.go`

- [ ] **Step 1: Write the failing tests**

Create `internal/modules/packages/unattended/module_test.go`:

```go
package unattended_test

import (
	"context"
	"testing"

	"github.com/maestroi/hardener/internal/executor"
	"github.com/maestroi/hardener/internal/model"
	unattendedmod "github.com/maestroi/hardener/internal/modules/packages/unattended"
	"github.com/maestroi/hardener/internal/testhelpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUnattended_Metadata(t *testing.T) {
	m := unattendedmod.New()
	meta := m.Metadata()
	assert.Equal(t, "pkgs-unattended-upgrades", meta.ID)
	assert.Contains(t, meta.SupportedDistros, "ubuntu")
	assert.True(t, meta.CanRollback)
}

func TestUnattended_SupportedFindings(t *testing.T) {
	assert.Contains(t, unattendedmod.New().SupportedFindings(), "PKGS-7370")
}

func TestUnattended_Plan_AlreadyInstalledAndEnabled_NotApplicable(t *testing.T) {
	inspect := &testhelpers.FakeInspector{
		InstalledPkgs: map[string]bool{"unattended-upgrades": true},
		Services: map[string]executor.ServiceStatus{
			"unattended-upgrades": {Name: "unattended-upgrades", Active: true, Enabled: true},
		},
	}
	m := unattendedmod.New()
	action, err := m.Plan(context.Background(), &model.Finding{ID: "PKGS-7370"}, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.False(t, action.Applicable)
	assert.NotEmpty(t, action.SkipReason)
}

func TestUnattended_Plan_NotInstalled_Applicable(t *testing.T) {
	inspect := &testhelpers.FakeInspector{
		InstalledPkgs: map[string]bool{},
	}
	m := unattendedmod.New()
	action, err := m.Plan(context.Background(), &model.Finding{ID: "PKGS-7370"}, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.True(t, action.Applicable)
}

func TestUnattended_Plan_InstalledButDisabled_Applicable(t *testing.T) {
	inspect := &testhelpers.FakeInspector{
		InstalledPkgs: map[string]bool{"unattended-upgrades": true},
		Services: map[string]executor.ServiceStatus{
			"unattended-upgrades": {Name: "unattended-upgrades", Active: false, Enabled: false},
		},
	}
	m := unattendedmod.New()
	action, err := m.Plan(context.Background(), &model.Finding{ID: "PKGS-7370"}, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.True(t, action.Applicable)
}

func TestUnattended_Apply_InstallsAndEnablesService(t *testing.T) {
	exec := &testhelpers.FakeExecutor{
		FakeInspector: testhelpers.FakeInspector{
			InstalledPkgs: map[string]bool{},
		},
	}
	m := unattendedmod.New()
	action := &model.PlannedAction{FindingID: "PKGS-7370", ModuleID: "pkgs-unattended-upgrades"}

	applied, err := m.Apply(context.Background(), action, exec)
	require.NoError(t, err)
	assert.Equal(t, model.ActionApplied, applied.Status)
	assert.True(t, exec.PackageInstalled("unattended-upgrades"))
	assert.True(t, testhelpers.ContainsService(exec.EnabledServices, "unattended-upgrades"))
	assert.True(t, testhelpers.ContainsService(exec.StartedServices, "unattended-upgrades"))
}

func TestUnattended_Apply_AlreadyInstalled_OnlyEnablesService(t *testing.T) {
	exec := &testhelpers.FakeExecutor{
		FakeInspector: testhelpers.FakeInspector{
			InstalledPkgs: map[string]bool{"unattended-upgrades": true},
		},
	}
	m := unattendedmod.New()
	action := &model.PlannedAction{
		FindingID: "PKGS-7370",
		ModuleID:  "pkgs-unattended-upgrades",
		Metadata:  map[string]string{"skip_install": "true"},
	}

	_, err := m.Apply(context.Background(), action, exec)
	require.NoError(t, err)
	assert.Empty(t, exec.InstalledPackages, "should not reinstall if skip_install set")
	assert.True(t, testhelpers.ContainsService(exec.EnabledServices, "unattended-upgrades"))
}

func TestUnattended_Validate_ActiveAndEnabled_NoError(t *testing.T) {
	inspect := &testhelpers.FakeInspector{
		InstalledPkgs: map[string]bool{"unattended-upgrades": true},
		Services: map[string]executor.ServiceStatus{
			"unattended-upgrades": {Name: "unattended-upgrades", Active: true, Enabled: true},
		},
	}
	m := unattendedmod.New()
	err := m.Validate(context.Background(), &model.PlannedAction{FindingID: "PKGS-7370"}, inspect)
	assert.NoError(t, err)
}

func TestUnattended_Validate_Inactive_Error(t *testing.T) {
	inspect := &testhelpers.FakeInspector{
		InstalledPkgs: map[string]bool{"unattended-upgrades": true},
		Services: map[string]executor.ServiceStatus{
			"unattended-upgrades": {Name: "unattended-upgrades", Active: false, Enabled: true},
		},
	}
	m := unattendedmod.New()
	err := m.Validate(context.Background(), &model.PlannedAction{FindingID: "PKGS-7370"}, inspect)
	assert.Error(t, err)
}
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
go test ./internal/modules/packages/unattended/... -v
```

Expected: FAIL.

- [ ] **Step 3: Write the module**

Create `internal/modules/packages/unattended/module.go`:

```go
package unattended

import (
	"context"
	"fmt"
	"time"

	"github.com/maestroi/hardener/internal/executor"
	"github.com/maestroi/hardener/internal/model"
	"github.com/maestroi/hardener/internal/modules"
)

const (
	packageName = "unattended-upgrades"
	serviceName = "unattended-upgrades"
)

// Module remediates PKGS-7370 by installing and enabling unattended-upgrades.
type Module struct{}

func New() *Module { return &Module{} }

func (m *Module) Metadata() modules.ModuleMetadata {
	return modules.ModuleMetadata{
		ID:               "pkgs-unattended-upgrades",
		Name:             "Enable Unattended Upgrades",
		Description:      "Installs and enables unattended-upgrades to apply security patches automatically",
		Category:         "Software",
		DefaultRisk:      model.RiskLow,
		SupportedDistros: []string{"ubuntu"},
		Tags:             []string{"network-safe", "docker-safe"},
		CanRollback:      true,
		RequiresReboot:   false,
	}
}

func (m *Module) SupportedFindings() []string {
	return []string{"PKGS-7370"}
}

func (m *Module) Plan(ctx context.Context, finding *model.Finding, _ *model.Profile, inspect executor.Inspector) (*model.PlannedAction, error) {
	meta := m.Metadata()

	installed, err := inspect.IsPackageInstalled(ctx, packageName)
	if err != nil {
		return nil, fmt.Errorf("checking %s: %w", packageName, err)
	}

	svcState, err := inspect.ServiceState(ctx, serviceName)
	if err != nil {
		return nil, fmt.Errorf("checking service %s: %w", serviceName, err)
	}

	if installed && svcState.Active && svcState.Enabled {
		return &model.PlannedAction{
			FindingID:  finding.ID,
			ModuleID:   meta.ID,
			Applicable: false,
			SkipReason: fmt.Sprintf("package %s is installed and service is active/enabled", packageName),
		}, nil
	}

	metadata := map[string]string{"package": packageName, "service": serviceName}
	if installed {
		metadata["skip_install"] = "true"
	}

	var steps []string
	if !installed {
		steps = append(steps, fmt.Sprintf("apt-get install -y %s", packageName))
	}
	steps = append(steps, fmt.Sprintf("systemctl enable %s", serviceName))
	steps = append(steps, fmt.Sprintf("systemctl start %s", serviceName))

	return &model.PlannedAction{
		FindingID:   finding.ID,
		ModuleID:    meta.ID,
		Title:       "Enable unattended-upgrades",
		Description: "Install and enable automatic security patching via unattended-upgrades",
		Steps:       steps,
		Metadata:    metadata,
		Risk:        model.RiskLow,
		CanRollback: true,
		Applicable:  true,
		Tags:        []string{"network-safe", "docker-safe"},
	}, nil
}

func (m *Module) Apply(ctx context.Context, action *model.PlannedAction, exec executor.Executor) (*model.AppliedAction, error) {
	if action.Metadata["skip_install"] != "true" {
		if err := exec.InstallPackage(ctx, packageName); err != nil {
			return nil, fmt.Errorf("installing %s: %w", packageName, err)
		}
	}
	if err := exec.EnableService(ctx, serviceName); err != nil {
		return nil, fmt.Errorf("enabling %s: %w", serviceName, err)
	}
	if err := exec.StartService(ctx, serviceName); err != nil {
		return nil, fmt.Errorf("starting %s: %w", serviceName, err)
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
		return fmt.Errorf("checking %s: %w", packageName, err)
	}
	if !ok {
		return fmt.Errorf("package %s not found after apply", packageName)
	}

	state, err := inspect.ServiceState(ctx, serviceName)
	if err != nil {
		return fmt.Errorf("checking service %s: %w", serviceName, err)
	}
	if !state.Active {
		return fmt.Errorf("service %s is not active after apply", serviceName)
	}
	return nil
}

func (m *Module) Rollback(_ context.Context, entry *model.RollbackEntry, _ executor.Executor) error {
	switch entry.Kind {
	case model.RollbackPackage:
		// MVP: skip removal to avoid dependency surprises.
		return nil
	case model.RollbackService:
		// Service rollback handled by the generic rollback manager.
		return nil
	default:
		return fmt.Errorf("pkgs-unattended-upgrades rollback: unexpected kind %q", entry.Kind)
	}
}
```

- [ ] **Step 4: Run tests**

```bash
go test ./internal/modules/packages/unattended/... -v
```

Expected: PASS — 7 tests.

- [ ] **Step 5: Commit**

```bash
git add internal/modules/packages/unattended/
git commit -m "feat: add PKGS-7370 unattended-upgrades module"
```

---

## Task 3: BANN-7126 + BANN-7130 — login banner module

Lynis findings: "Add a legal banner to /etc/issue" (7126) and "Add legal banner to /etc/issue.net" (7130).
Fix: write a standard legal warning to both files if they are empty or missing a legal notice.
One module handles both findings — same logic, different target path.

**Files:**
- Create: `testdata/banner/issue_empty`
- Create: `testdata/banner/issue_set`
- Create: `internal/modules/banner/module.go`
- Create: `internal/modules/banner/module_test.go`

- [ ] **Step 1: Create test fixtures**

Create `testdata/banner/issue_empty`:
```
Ubuntu 22.04.3 LTS \n \l
```

Create `testdata/banner/issue_set`:
```
****************************************************************************
AUTHORIZED ACCESS ONLY

This system is restricted to authorized users only. All activity may be
monitored and reported. Unauthorized access is prohibited and may result
in civil and/or criminal liability.

By proceeding, you consent to monitoring.
****************************************************************************
```

- [ ] **Step 2: Write the failing tests**

Create `internal/modules/banner/module_test.go`:

```go
package banner_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/maestroi/hardener/internal/model"
	bannermod "github.com/maestroi/hardener/internal/modules/banner"
	"github.com/maestroi/hardener/internal/testhelpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func loadBannerFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("../../../testdata/banner", name))
	require.NoError(t, err)
	return data
}

func TestBanner_Metadata(t *testing.T) {
	m := bannermod.New()
	meta := m.Metadata()
	assert.Equal(t, "banner-legal", meta.ID)
	assert.Contains(t, meta.SupportedDistros, "ubuntu")
	assert.True(t, meta.CanRollback)
}

func TestBanner_SupportedFindings(t *testing.T) {
	findings := bannermod.New().SupportedFindings()
	assert.Contains(t, findings, "BANN-7126")
	assert.Contains(t, findings, "BANN-7130")
}

func TestBanner_Plan_BANN7126_EmptyIssue_Applicable(t *testing.T) {
	content := loadBannerFixture(t, "issue_empty")
	inspect := &testhelpers.FakeInspector{
		Files: map[string][]byte{bannermod.IssuePath: content},
	}
	m := bannermod.New()
	action, err := m.Plan(context.Background(), &model.Finding{ID: "BANN-7126"}, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.True(t, action.Applicable)
	assert.Contains(t, action.Metadata, "target_file")
	assert.Equal(t, bannermod.IssuePath, action.Metadata["target_file"])
}

func TestBanner_Plan_BANN7130_EmptyIssueNet_Applicable(t *testing.T) {
	inspect := &testhelpers.FakeInspector{
		Files: map[string][]byte{bannermod.IssueNetPath: []byte("")},
	}
	m := bannermod.New()
	action, err := m.Plan(context.Background(), &model.Finding{ID: "BANN-7130"}, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.True(t, action.Applicable)
	assert.Equal(t, bannermod.IssueNetPath, action.Metadata["target_file"])
}

func TestBanner_Plan_AlreadySet_NotApplicable(t *testing.T) {
	content := loadBannerFixture(t, "issue_set")
	inspect := &testhelpers.FakeInspector{
		Files: map[string][]byte{bannermod.IssuePath: content},
	}
	m := bannermod.New()
	action, err := m.Plan(context.Background(), &model.Finding{ID: "BANN-7126"}, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.False(t, action.Applicable)
	assert.NotEmpty(t, action.SkipReason)
}

func TestBanner_Plan_FileMissing_Applicable(t *testing.T) {
	inspect := &testhelpers.FakeInspector{Files: map[string][]byte{}}
	m := bannermod.New()
	action, err := m.Plan(context.Background(), &model.Finding{ID: "BANN-7126"}, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.True(t, action.Applicable)
}

func TestBanner_Apply_WritesLegalBanner(t *testing.T) {
	exec := &testhelpers.FakeExecutor{
		FakeInspector: testhelpers.FakeInspector{
			Files: map[string][]byte{bannermod.IssuePath: []byte("Ubuntu 22.04")},
		},
	}
	m := bannermod.New()
	action := &model.PlannedAction{
		FindingID: "BANN-7126",
		ModuleID:  "banner-legal",
		Metadata:  map[string]string{"target_file": bannermod.IssuePath},
	}

	applied, err := m.Apply(context.Background(), action, exec)
	require.NoError(t, err)
	assert.Equal(t, model.ActionApplied, applied.Status)
	assert.True(t, exec.HasWritten(bannermod.IssuePath))
	assert.True(t, exec.FileContains(bannermod.IssuePath, "AUTHORIZED ACCESS ONLY"))
}

func TestBanner_Validate_BannerPresent_NoError(t *testing.T) {
	content := loadBannerFixture(t, "issue_set")
	inspect := &testhelpers.FakeInspector{
		Files: map[string][]byte{bannermod.IssuePath: content},
	}
	m := bannermod.New()
	err := m.Validate(context.Background(), &model.PlannedAction{
		FindingID: "BANN-7126",
		Metadata:  map[string]string{"target_file": bannermod.IssuePath},
	}, inspect)
	assert.NoError(t, err)
}

func TestBanner_Rollback_RestoresFile(t *testing.T) {
	originalContent := []byte("Ubuntu 22.04")
	exec := &testhelpers.FakeExecutor{
		FakeInspector: testhelpers.FakeInspector{
			Files: map[string][]byte{"/tmp/backup": originalContent},
		},
	}
	m := bannermod.New()
	entry := &model.RollbackEntry{
		Kind:       model.RollbackFile,
		Path:       bannermod.IssuePath,
		BackupPath: "/tmp/backup",
		OrigMode:   0644,
	}
	err := m.Rollback(context.Background(), entry, exec)
	require.NoError(t, err)
	assert.True(t, exec.HasWritten(bannermod.IssuePath))
}
```

- [ ] **Step 3: Run tests to confirm they fail**

```bash
go test ./internal/modules/banner/... -v
```

Expected: FAIL.

- [ ] **Step 4: Write the module**

Create `internal/modules/banner/module.go`:

```go
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
```

- [ ] **Step 5: Run tests**

```bash
go test ./internal/modules/banner/... -v
```

Expected: PASS — 8 tests.

- [ ] **Step 6: Commit**

```bash
git add testdata/banner/ internal/modules/banner/
git commit -m "feat: add BANN-7126/7130 legal banner module"
```

---

## Task 4: LOGG-2154 — logrotate compression module

Lynis finding: "Enable logrotate compression to reduce log file disk usage."
Fix: ensure `/etc/logrotate.conf` contains the `compress` directive in its global options block.

**Files:**
- Create: `testdata/logrotate/logrotate.conf_default`
- Create: `testdata/logrotate/logrotate.conf_compressed`
- Create: `internal/modules/logging/logrotate/module.go`
- Create: `internal/modules/logging/logrotate/module_test.go`

- [ ] **Step 1: Create test fixtures**

Create `testdata/logrotate/logrotate.conf_default`:
```
# see "man logrotate" for details
# global options do not affect preceding include directives

# rotate log files weekly
weekly

# use the adm group by default, since this is the group /var/log/syslog uses
su root adm

# keep 4 weeks worth of backlogs
rotate 4

# create new (empty) log files after rotating old ones
create

# use date as a suffix of the rotated file
#dateext

# uncomment this if you want your log files compressed
#compress

# packages drop log rotation information into this directory
include /etc/logrotate.d

# system-specific logs may be also be configured here.
```

Create `testdata/logrotate/logrotate.conf_compressed`:
```
# see "man logrotate" for details
# global options do not affect preceding include directives

# rotate log files weekly
weekly

# use the adm group by default, since this is the group /var/log/syslog uses
su root adm

# keep 4 weeks worth of backlogs
rotate 4

# create new (empty) log files after rotating old ones
create

# enabled by hardener
compress

# packages drop log rotation information into this directory
include /etc/logrotate.d

# system-specific logs may be also be configured here.
```

- [ ] **Step 2: Write the failing tests**

Create `internal/modules/logging/logrotate/module_test.go`:

```go
package logrotate_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/maestroi/hardener/internal/model"
	logrotatemod "github.com/maestroi/hardener/internal/modules/logging/logrotate"
	"github.com/maestroi/hardener/internal/testhelpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("../../../testdata/logrotate", name))
	require.NoError(t, err)
	return data
}

func TestLogrotate_Metadata(t *testing.T) {
	m := logrotatemod.New()
	meta := m.Metadata()
	assert.Equal(t, "logging-logrotate-compress", meta.ID)
	assert.Contains(t, meta.SupportedDistros, "ubuntu")
	assert.True(t, meta.CanRollback)
}

func TestLogrotate_SupportedFindings(t *testing.T) {
	assert.Contains(t, logrotatemod.New().SupportedFindings(), "LOGG-2154")
}

func TestLogrotate_Plan_CompressAlreadySet_NotApplicable(t *testing.T) {
	content := loadFixture(t, "logrotate.conf_compressed")
	inspect := &testhelpers.FakeInspector{
		Files: map[string][]byte{logrotatemod.ConfigPath: content},
	}
	m := logrotatemod.New()
	action, err := m.Plan(context.Background(), &model.Finding{ID: "LOGG-2154"}, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.False(t, action.Applicable)
	assert.NotEmpty(t, action.SkipReason)
}

func TestLogrotate_Plan_CompressMissing_Applicable(t *testing.T) {
	content := loadFixture(t, "logrotate.conf_default")
	inspect := &testhelpers.FakeInspector{
		Files: map[string][]byte{logrotatemod.ConfigPath: content},
	}
	m := logrotatemod.New()
	action, err := m.Plan(context.Background(), &model.Finding{ID: "LOGG-2154"}, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.True(t, action.Applicable)
	assert.Contains(t, action.Metadata, "target_file")
}

func TestLogrotate_Plan_FileNotFound_NotApplicable(t *testing.T) {
	inspect := &testhelpers.FakeInspector{Files: map[string][]byte{}}
	m := logrotatemod.New()
	action, err := m.Plan(context.Background(), &model.Finding{ID: "LOGG-2154"}, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.False(t, action.Applicable)
	assert.Contains(t, action.SkipReason, "not found")
}

func TestLogrotate_Apply_AddsCompress(t *testing.T) {
	content := loadFixture(t, "logrotate.conf_default")
	exec := &testhelpers.FakeExecutor{
		FakeInspector: testhelpers.FakeInspector{
			Files: map[string][]byte{logrotatemod.ConfigPath: content},
		},
	}
	m := logrotatemod.New()
	action := &model.PlannedAction{
		FindingID: "LOGG-2154",
		ModuleID:  "logging-logrotate-compress",
		Metadata:  map[string]string{"target_file": logrotatemod.ConfigPath},
	}

	applied, err := m.Apply(context.Background(), action, exec)
	require.NoError(t, err)
	assert.Equal(t, model.ActionApplied, applied.Status)
	assert.True(t, exec.HasWritten(logrotatemod.ConfigPath))
	assert.True(t, exec.FileContains(logrotatemod.ConfigPath, "\ncompress\n"))
}

func TestLogrotate_Validate_CompressPresent_NoError(t *testing.T) {
	content := loadFixture(t, "logrotate.conf_compressed")
	inspect := &testhelpers.FakeInspector{
		Files: map[string][]byte{logrotatemod.ConfigPath: content},
	}
	m := logrotatemod.New()
	err := m.Validate(context.Background(), &model.PlannedAction{
		FindingID: "LOGG-2154",
		Metadata:  map[string]string{"target_file": logrotatemod.ConfigPath},
	}, inspect)
	assert.NoError(t, err)
}

func TestLogrotate_Validate_CommentedCompress_Error(t *testing.T) {
	content := loadFixture(t, "logrotate.conf_default") // has #compress
	inspect := &testhelpers.FakeInspector{
		Files: map[string][]byte{logrotatemod.ConfigPath: content},
	}
	m := logrotatemod.New()
	err := m.Validate(context.Background(), &model.PlannedAction{
		FindingID: "LOGG-2154",
		Metadata:  map[string]string{"target_file": logrotatemod.ConfigPath},
	}, inspect)
	assert.Error(t, err)
}

func TestLogrotate_Rollback_RestoresFile(t *testing.T) {
	original := loadFixture(t, "logrotate.conf_default")
	exec := &testhelpers.FakeExecutor{
		FakeInspector: testhelpers.FakeInspector{
			Files: map[string][]byte{"/tmp/backup": original},
		},
	}
	m := logrotatemod.New()
	entry := &model.RollbackEntry{
		Kind:       model.RollbackFile,
		Path:       logrotatemod.ConfigPath,
		BackupPath: "/tmp/backup",
		OrigMode:   0644,
	}
	err := m.Rollback(context.Background(), entry, exec)
	require.NoError(t, err)
	assert.True(t, exec.HasWritten(logrotatemod.ConfigPath))
}
```

- [ ] **Step 3: Run tests to confirm they fail**

```bash
go test ./internal/modules/logging/logrotate/... -v
```

Expected: FAIL.

- [ ] **Step 4: Write the module**

Create `internal/modules/logging/logrotate/module.go`:

```go
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
```

- [ ] **Step 5: Run tests**

```bash
go test ./internal/modules/logging/logrotate/... -v
```

Expected: PASS — 7 tests.

- [ ] **Step 6: Commit**

```bash
git add testdata/logrotate/ internal/modules/logging/logrotate/
git commit -m "feat: add LOGG-2154 logrotate compression module"
```

---

## Task 5: ACCT-9622 — process accounting (acct) module

Lynis finding: "Enable process accounting."
Fix: install the `acct` package and enable/start the `acct` service.

**Files:**
- Create: `internal/modules/accounting/acct/module.go`
- Create: `internal/modules/accounting/acct/module_test.go`

- [ ] **Step 1: Write the failing tests**

Create `internal/modules/accounting/acct/module_test.go`:

```go
package acct_test

import (
	"context"
	"testing"

	"github.com/maestroi/hardener/internal/executor"
	"github.com/maestroi/hardener/internal/model"
	acctmod "github.com/maestroi/hardener/internal/modules/accounting/acct"
	"github.com/maestroi/hardener/internal/testhelpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAcct_Metadata(t *testing.T) {
	m := acctmod.New()
	meta := m.Metadata()
	assert.Equal(t, "accounting-acct", meta.ID)
	assert.Contains(t, meta.SupportedDistros, "ubuntu")
	assert.True(t, meta.CanRollback)
}

func TestAcct_SupportedFindings(t *testing.T) {
	assert.Contains(t, acctmod.New().SupportedFindings(), "ACCT-9622")
}

func TestAcct_Plan_InstalledAndEnabled_NotApplicable(t *testing.T) {
	inspect := &testhelpers.FakeInspector{
		InstalledPkgs: map[string]bool{"acct": true},
		Services: map[string]executor.ServiceStatus{
			"acct": {Name: "acct", Active: true, Enabled: true},
		},
	}
	m := acctmod.New()
	action, err := m.Plan(context.Background(), &model.Finding{ID: "ACCT-9622"}, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.False(t, action.Applicable)
}

func TestAcct_Plan_NotInstalled_Applicable(t *testing.T) {
	inspect := &testhelpers.FakeInspector{InstalledPkgs: map[string]bool{}}
	m := acctmod.New()
	action, err := m.Plan(context.Background(), &model.Finding{ID: "ACCT-9622"}, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.True(t, action.Applicable)
}

func TestAcct_Apply_InstallsEnablesStarts(t *testing.T) {
	exec := &testhelpers.FakeExecutor{
		FakeInspector: testhelpers.FakeInspector{InstalledPkgs: map[string]bool{}},
	}
	m := acctmod.New()
	action := &model.PlannedAction{FindingID: "ACCT-9622", ModuleID: "accounting-acct"}

	applied, err := m.Apply(context.Background(), action, exec)
	require.NoError(t, err)
	assert.Equal(t, model.ActionApplied, applied.Status)
	assert.True(t, exec.PackageInstalled("acct"))
	assert.True(t, testhelpers.ContainsService(exec.EnabledServices, "acct"))
	assert.True(t, testhelpers.ContainsService(exec.StartedServices, "acct"))
}

func TestAcct_Validate_ActiveAndEnabled_NoError(t *testing.T) {
	inspect := &testhelpers.FakeInspector{
		InstalledPkgs: map[string]bool{"acct": true},
		Services: map[string]executor.ServiceStatus{
			"acct": {Name: "acct", Active: true, Enabled: true},
		},
	}
	m := acctmod.New()
	err := m.Validate(context.Background(), &model.PlannedAction{FindingID: "ACCT-9622"}, inspect)
	assert.NoError(t, err)
}

func TestAcct_Validate_Inactive_Error(t *testing.T) {
	inspect := &testhelpers.FakeInspector{
		InstalledPkgs: map[string]bool{"acct": true},
		Services: map[string]executor.ServiceStatus{
			"acct": {Name: "acct", Active: false, Enabled: true},
		},
	}
	m := acctmod.New()
	err := m.Validate(context.Background(), &model.PlannedAction{FindingID: "ACCT-9622"}, inspect)
	assert.Error(t, err)
}
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
go test ./internal/modules/accounting/acct/... -v
```

Expected: FAIL.

- [ ] **Step 3: Write the module**

Create `internal/modules/accounting/acct/module.go`:

```go
package acct

import (
	"context"
	"fmt"
	"time"

	"github.com/maestroi/hardener/internal/executor"
	"github.com/maestroi/hardener/internal/model"
	"github.com/maestroi/hardener/internal/modules"
)

const (
	packageName = "acct"
	serviceName = "acct"
)

// Module remediates ACCT-9622 by installing process accounting (acct).
type Module struct{}

func New() *Module { return &Module{} }

func (m *Module) Metadata() modules.ModuleMetadata {
	return modules.ModuleMetadata{
		ID:               "accounting-acct",
		Name:             "Enable Process Accounting",
		Description:      "Installs and enables the acct daemon for per-user process and login accounting",
		Category:         "Accounting",
		DefaultRisk:      model.RiskLow,
		SupportedDistros: []string{"ubuntu"},
		Tags:             []string{"network-safe", "docker-safe"},
		CanRollback:      true,
		RequiresReboot:   false,
	}
}

func (m *Module) SupportedFindings() []string {
	return []string{"ACCT-9622"}
}

func (m *Module) Plan(ctx context.Context, finding *model.Finding, _ *model.Profile, inspect executor.Inspector) (*model.PlannedAction, error) {
	meta := m.Metadata()

	installed, err := inspect.IsPackageInstalled(ctx, packageName)
	if err != nil {
		return nil, fmt.Errorf("checking %s: %w", packageName, err)
	}

	svcState, err := inspect.ServiceState(ctx, serviceName)
	if err != nil {
		return nil, fmt.Errorf("checking service %s: %w", serviceName, err)
	}

	if installed && svcState.Active && svcState.Enabled {
		return &model.PlannedAction{
			FindingID:  finding.ID,
			ModuleID:   meta.ID,
			Applicable: false,
			SkipReason: fmt.Sprintf("package %s is installed and service is active/enabled", packageName),
		}, nil
	}

	metadata := map[string]string{"package": packageName, "service": serviceName}
	if installed {
		metadata["skip_install"] = "true"
	}

	var steps []string
	if !installed {
		steps = append(steps, fmt.Sprintf("apt-get install -y %s", packageName))
	}
	steps = append(steps, fmt.Sprintf("systemctl enable %s", serviceName))
	steps = append(steps, fmt.Sprintf("systemctl start %s", serviceName))

	return &model.PlannedAction{
		FindingID:   finding.ID,
		ModuleID:    meta.ID,
		Title:       "Enable process accounting",
		Description: "Install acct and enable the process accounting daemon",
		Steps:       steps,
		Metadata:    metadata,
		Risk:        model.RiskLow,
		CanRollback: true,
		Applicable:  true,
		Tags:        []string{"network-safe", "docker-safe"},
	}, nil
}

func (m *Module) Apply(ctx context.Context, action *model.PlannedAction, exec executor.Executor) (*model.AppliedAction, error) {
	if action.Metadata["skip_install"] != "true" {
		if err := exec.InstallPackage(ctx, packageName); err != nil {
			return nil, fmt.Errorf("installing %s: %w", packageName, err)
		}
	}
	if err := exec.EnableService(ctx, serviceName); err != nil {
		return nil, fmt.Errorf("enabling %s: %w", serviceName, err)
	}
	if err := exec.StartService(ctx, serviceName); err != nil {
		return nil, fmt.Errorf("starting %s: %w", serviceName, err)
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
		return fmt.Errorf("checking %s: %w", packageName, err)
	}
	if !ok {
		return fmt.Errorf("package %s not found after apply", packageName)
	}

	state, err := inspect.ServiceState(ctx, serviceName)
	if err != nil {
		return fmt.Errorf("checking service %s: %w", serviceName, err)
	}
	if !state.Active {
		return fmt.Errorf("service %s not active after apply", serviceName)
	}
	return nil
}

func (m *Module) Rollback(_ context.Context, entry *model.RollbackEntry, _ executor.Executor) error {
	switch entry.Kind {
	case model.RollbackPackage, model.RollbackService:
		return nil
	default:
		return fmt.Errorf("accounting-acct rollback: unexpected kind %q", entry.Kind)
	}
}
```

- [ ] **Step 4: Run tests**

```bash
go test ./internal/modules/accounting/acct/... -v
```

Expected: PASS — 5 tests.

- [ ] **Step 5: Commit**

```bash
git add internal/modules/accounting/acct/
git commit -m "feat: add ACCT-9622 process accounting (acct) module"
```

---

## Task 6: ACCT-9626 — auditd module

Lynis finding: "Enable auditd for kernel-level audit logging."
Fix: install the `auditd` package and enable/start the `auditd` service.

**Files:**
- Create: `internal/modules/accounting/auditd/module.go`
- Create: `internal/modules/accounting/auditd/module_test.go`

- [ ] **Step 1: Write the failing tests**

Create `internal/modules/accounting/auditd/module_test.go`:

```go
package auditd_test

import (
	"context"
	"testing"

	"github.com/maestroi/hardener/internal/executor"
	"github.com/maestroi/hardener/internal/model"
	auditdmod "github.com/maestroi/hardener/internal/modules/accounting/auditd"
	"github.com/maestroi/hardener/internal/testhelpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuditd_Metadata(t *testing.T) {
	m := auditdmod.New()
	meta := m.Metadata()
	assert.Equal(t, "accounting-auditd", meta.ID)
	assert.Contains(t, meta.SupportedDistros, "ubuntu")
	assert.True(t, meta.CanRollback)
}

func TestAuditd_SupportedFindings(t *testing.T) {
	assert.Contains(t, auditdmod.New().SupportedFindings(), "ACCT-9626")
}

func TestAuditd_Plan_InstalledAndEnabled_NotApplicable(t *testing.T) {
	inspect := &testhelpers.FakeInspector{
		InstalledPkgs: map[string]bool{"auditd": true},
		Services: map[string]executor.ServiceStatus{
			"auditd": {Name: "auditd", Active: true, Enabled: true},
		},
	}
	m := auditdmod.New()
	action, err := m.Plan(context.Background(), &model.Finding{ID: "ACCT-9626"}, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.False(t, action.Applicable)
}

func TestAuditd_Plan_NotInstalled_Applicable(t *testing.T) {
	inspect := &testhelpers.FakeInspector{InstalledPkgs: map[string]bool{}}
	m := auditdmod.New()
	action, err := m.Plan(context.Background(), &model.Finding{ID: "ACCT-9626"}, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.True(t, action.Applicable)
}

func TestAuditd_Apply_InstallsEnablesStarts(t *testing.T) {
	exec := &testhelpers.FakeExecutor{
		FakeInspector: testhelpers.FakeInspector{InstalledPkgs: map[string]bool{}},
	}
	m := auditdmod.New()
	action := &model.PlannedAction{FindingID: "ACCT-9626", ModuleID: "accounting-auditd"}

	applied, err := m.Apply(context.Background(), action, exec)
	require.NoError(t, err)
	assert.Equal(t, model.ActionApplied, applied.Status)
	assert.True(t, exec.PackageInstalled("auditd"))
	assert.True(t, testhelpers.ContainsService(exec.EnabledServices, "auditd"))
	assert.True(t, testhelpers.ContainsService(exec.StartedServices, "auditd"))
}

func TestAuditd_Validate_ActiveAndEnabled_NoError(t *testing.T) {
	inspect := &testhelpers.FakeInspector{
		InstalledPkgs: map[string]bool{"auditd": true},
		Services: map[string]executor.ServiceStatus{
			"auditd": {Name: "auditd", Active: true, Enabled: true},
		},
	}
	m := auditdmod.New()
	err := m.Validate(context.Background(), &model.PlannedAction{FindingID: "ACCT-9626"}, inspect)
	assert.NoError(t, err)
}

func TestAuditd_Validate_NotInstalled_Error(t *testing.T) {
	inspect := &testhelpers.FakeInspector{InstalledPkgs: map[string]bool{}}
	m := auditdmod.New()
	err := m.Validate(context.Background(), &model.PlannedAction{FindingID: "ACCT-9626"}, inspect)
	assert.Error(t, err)
}
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
go test ./internal/modules/accounting/auditd/... -v
```

Expected: FAIL.

- [ ] **Step 3: Write the module**

Create `internal/modules/accounting/auditd/module.go`:

```go
package auditd

import (
	"context"
	"fmt"
	"time"

	"github.com/maestroi/hardener/internal/executor"
	"github.com/maestroi/hardener/internal/model"
	"github.com/maestroi/hardener/internal/modules"
)

const (
	packageName = "auditd"
	serviceName = "auditd"
)

// Module remediates ACCT-9626 by installing and enabling auditd.
type Module struct{}

func New() *Module { return &Module{} }

func (m *Module) Metadata() modules.ModuleMetadata {
	return modules.ModuleMetadata{
		ID:               "accounting-auditd",
		Name:             "Enable auditd",
		Description:      "Installs and enables auditd for kernel-level audit event logging",
		Category:         "Accounting",
		DefaultRisk:      model.RiskLow,
		SupportedDistros: []string{"ubuntu"},
		Tags:             []string{"network-safe", "docker-safe"},
		CanRollback:      true,
		RequiresReboot:   false,
	}
}

func (m *Module) SupportedFindings() []string {
	return []string{"ACCT-9626"}
}

func (m *Module) Plan(ctx context.Context, finding *model.Finding, _ *model.Profile, inspect executor.Inspector) (*model.PlannedAction, error) {
	meta := m.Metadata()

	installed, err := inspect.IsPackageInstalled(ctx, packageName)
	if err != nil {
		return nil, fmt.Errorf("checking %s: %w", packageName, err)
	}

	svcState, err := inspect.ServiceState(ctx, serviceName)
	if err != nil {
		return nil, fmt.Errorf("checking service %s: %w", serviceName, err)
	}

	if installed && svcState.Active && svcState.Enabled {
		return &model.PlannedAction{
			FindingID:  finding.ID,
			ModuleID:   meta.ID,
			Applicable: false,
			SkipReason: fmt.Sprintf("package %s is installed and service is active/enabled", packageName),
		}, nil
	}

	metadata := map[string]string{"package": packageName, "service": serviceName}
	if installed {
		metadata["skip_install"] = "true"
	}

	var steps []string
	if !installed {
		steps = append(steps, fmt.Sprintf("apt-get install -y %s", packageName))
	}
	steps = append(steps, fmt.Sprintf("systemctl enable %s", serviceName))
	steps = append(steps, fmt.Sprintf("systemctl start %s", serviceName))

	return &model.PlannedAction{
		FindingID:   finding.ID,
		ModuleID:    meta.ID,
		Title:       "Enable auditd",
		Description: "Install auditd and enable kernel audit event logging",
		Steps:       steps,
		Metadata:    metadata,
		Risk:        model.RiskLow,
		CanRollback: true,
		Applicable:  true,
		Tags:        []string{"network-safe", "docker-safe"},
	}, nil
}

func (m *Module) Apply(ctx context.Context, action *model.PlannedAction, exec executor.Executor) (*model.AppliedAction, error) {
	if action.Metadata["skip_install"] != "true" {
		if err := exec.InstallPackage(ctx, packageName); err != nil {
			return nil, fmt.Errorf("installing %s: %w", packageName, err)
		}
	}
	if err := exec.EnableService(ctx, serviceName); err != nil {
		return nil, fmt.Errorf("enabling %s: %w", serviceName, err)
	}
	if err := exec.StartService(ctx, serviceName); err != nil {
		return nil, fmt.Errorf("starting %s: %w", serviceName, err)
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
		return fmt.Errorf("checking %s: %w", packageName, err)
	}
	if !ok {
		return fmt.Errorf("package %s not found after apply", packageName)
	}

	state, err := inspect.ServiceState(ctx, serviceName)
	if err != nil {
		return fmt.Errorf("checking service %s: %w", serviceName, err)
	}
	if !state.Active {
		return fmt.Errorf("service %s not active after apply", serviceName)
	}
	return nil
}

func (m *Module) Rollback(_ context.Context, entry *model.RollbackEntry, _ executor.Executor) error {
	switch entry.Kind {
	case model.RollbackPackage, model.RollbackService:
		return nil
	default:
		return fmt.Errorf("accounting-auditd rollback: unexpected kind %q", entry.Kind)
	}
}
```

- [ ] **Step 4: Run tests**

```bash
go test ./internal/modules/accounting/auditd/... -v
```

Expected: PASS — 5 tests.

- [ ] **Step 5: Commit**

```bash
git add internal/modules/accounting/auditd/
git commit -m "feat: add ACCT-9626 auditd module"
```

---

## Task 7: Wire registry and verify dry-run

Register all six new modules in the registry so every Group 1 finding shows up as "planned" (not "no module registered") in dry-run output.

**Files:**
- Modify: `internal/registry/init.go`

- [ ] **Step 1: Write a registry test that asserts all new modules are registered**

Add to `internal/registry/registry_test.go` (append to existing test file):

```go
func TestRegistry_Default_ContainsGroup1Modules(t *testing.T) {
	r := Default()
	findingIDs := []string{
		"PKGS-7394",
		"PKGS-7370",
		"BANN-7126",
		"BANN-7130",
		"LOGG-2154",
		"ACCT-9622",
		"ACCT-9626",
	}
	for _, id := range findingIDs {
		mod, err := r.Lookup(id)
		assert.NoError(t, err, "finding %s should have a registered module", id)
		assert.NotNil(t, mod, "module for %s must not be nil", id)
	}
}
```

- [ ] **Step 2: Run to confirm it fails**

```bash
go test ./internal/registry/... -run TestRegistry_Default_ContainsGroup1Modules -v
```

Expected: FAIL — modules not registered yet.

- [ ] **Step 3: Update registry init.go**

Replace `internal/registry/init.go` with:

```go
package registry

import (
	acctmod    "github.com/maestroi/hardener/internal/modules/accounting/acct"
	auditdmod  "github.com/maestroi/hardener/internal/modules/accounting/auditd"
	bannermod  "github.com/maestroi/hardener/internal/modules/banner"
	logrotmod  "github.com/maestroi/hardener/internal/modules/logging/logrotate"
	debsumsmod "github.com/maestroi/hardener/internal/modules/packages/debsums"
	unattmod   "github.com/maestroi/hardener/internal/modules/packages/unattended"
	sshmod     "github.com/maestroi/hardener/internal/modules/ssh"
)

// Default returns the production registry with all bundled modules registered.
func Default() *Registry {
	r := New()
	r.Register(sshmod.New())
	r.Register(debsumsmod.New())
	r.Register(unattmod.New())
	r.Register(bannermod.New())
	r.Register(logrotmod.New())
	r.Register(acctmod.New())
	r.Register(auditdmod.New())
	return r
}
```

- [ ] **Step 4: Run registry test**

```bash
go test ./internal/registry/... -v
```

Expected: PASS — all findings resolve to a module.

- [ ] **Step 5: Run full test suite**

```bash
go test ./... 2>&1 | tail -30
```

Expected: all packages PASS, no compilation errors.

- [ ] **Step 6: Dry-run sanity check**

Build and run with a real or synthetic Lynis report that contains the new finding IDs. The existing `testdata/lynis-reports/basic.dat` only has a few findings. Create a synthetic test report to exercise all new modules:

```bash
cat > /tmp/test-group1.dat << 'EOF'
report_version_major=1
report_version_minor=2
lynis_version=3.0.9

suggestion[]=PKGS-7394|Install debsums utility to periodically verify installed packages.|
suggestion[]=PKGS-7370|Enable unattended package upgrades.|
suggestion[]=BANN-7126|Add a legal banner to /etc/issue.|
suggestion[]=BANN-7130|Add legal banner to /etc/issue.net.|
suggestion[]=LOGG-2154|Enable logrotate compression.|
suggestion[]=ACCT-9622|Enable process accounting.|
suggestion[]=ACCT-9626|Enable auditd.|
warning[]=SSH-7408|sshd option PermitRootLogin is not disabled|

hardening_index=42
EOF

go run ./cmd/hardener apply --dry-run --report /tmp/test-group1.dat
```

Expected output: all 7 findings show `[PLANNED]` with their module IDs. Zero findings show `no module registered`.

- [ ] **Step 7: Commit**

```bash
git add internal/registry/init.go internal/registry/registry_test.go
git commit -m "feat: register Group 1 modules — PKGS-7394/7370, BANN-7126/7130, LOGG-2154, ACCT-9622/9626"
```

---

## Self-Review

**Spec coverage:** All 6 findings from the Group 1 request are covered (PKGS-7394, PKGS-7370, BANN-7126, BANN-7130, LOGG-2154, ACCT-9622, ACCT-9626). Shared testhelpers prevent copy-paste of fakes across 6 test files.

**Placeholder scan:** No TBD/TODO. Every step has complete, compilable code. Every command shows expected output.

**Type consistency:**
- `testhelpers.FakeInspector` / `testhelpers.FakeExecutor` are referenced identically across all module tests.
- `modules.ModuleMetadata`, `model.PlannedAction`, `model.AppliedAction`, `model.RollbackEntry` types match existing definitions in `internal/modules/module.go`, `internal/model/action.go`, `internal/model/rollback.go`.
- All `Rollback()` signatures: `(ctx, *model.RollbackEntry, executor.Executor) error` — matches the Module interface.
- All `Plan()` signatures: `(ctx, *model.Finding, *model.Profile, executor.Inspector) (*model.PlannedAction, error)` — matches.
- `model.RollbackPackage`, `model.RollbackService`, `model.RollbackFile` constants exist in `internal/model/rollback.go`.

**Architecture conformance:** No module creates its own backups (BackupStore is pipeline-owned). Package rollback is a no-op for MVP (WasInstalled conservatism). No module imports from another module. Registry is the only file that imports concrete module types.
