# Hardener Group 2B: Authentication Modules Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement six authentication hardening modules: AUTH-9262 (PAM pwquality), AUTH-9286 (password aging), AUTH-9328 (umask), AUTH-9229 (PAM history), AUTH-9230 (pam_faillock), AUTH-9282 (sudoers permissions).

**Architecture:** All modules are stateless, following the Module interface. File-based modules use RollbackFile; package-only modules use RollbackPackage no-op. PAM modifications are conservative — faillock module only writes faillock.conf, not the PAM stack.

**Tech Stack:** Go 1.22, github.com/maestroi/hardener, testify.

---

## Context

### Module interface (from `internal/modules/module.go`)

```go
type Module interface {
    Metadata() ModuleMetadata
    SupportedFindings() []string
    Plan(ctx context.Context, finding *model.Finding, profile *model.Profile, inspect executor.Inspector) (*model.PlannedAction, error)
    Apply(ctx context.Context, action *model.PlannedAction, exec executor.Executor) (*model.AppliedAction, error)
    Validate(ctx context.Context, action *model.PlannedAction, inspect executor.Inspector) error
    Rollback(ctx context.Context, entry *model.RollbackEntry, exec executor.Executor) error
}
```

### Test helpers

`testhelpers.FakeInspector` and `testhelpers.FakeExecutor` are available from `github.com/maestroi/hardener/internal/testhelpers`. Use these in all test files — do not define inline fakes.

Key `FakeExecutor` methods relevant here:
- `PackageInstalled(name string) bool` — checks `InstallPackage` was called
- `FileContains(path, substr string) bool` — checks written file content
- `HasWritten(path string) bool` — checks write was called at all

### Real constants

| Symbol | Value |
|--------|-------|
| `model.RiskLow` | `RiskLevel(1)` |
| `model.RiskMedium` | `RiskLevel(2)` |
| `model.ActionApplied` | `ActionStatus("applied")` |
| `model.RollbackFile` | `RollbackKind("file")` |
| `model.RollbackPackage` | `RollbackKind("package")` |

---

## Module 1: AUTH-9262 — PAM Password Quality Package

**Package:** `internal/modules/auth/pwquality/`
**Module ID:** `auth-pam-pwquality`
**Risk:** RiskLow | **Tags:** `["network-safe", "docker-safe"]`

### Step 1.1 — Create module file

- [ ] Create `internal/modules/auth/pwquality/module.go`:

```go
package pwquality

import (
	"context"
	"fmt"
	"time"

	"github.com/maestroi/hardener/internal/executor"
	"github.com/maestroi/hardener/internal/model"
	"github.com/maestroi/hardener/internal/modules"
)

const packageName = "libpam-pwquality"

// Module remediates AUTH-9262 by ensuring libpam-pwquality is installed.
type Module struct{}

func New() *Module { return &Module{} }

func (m *Module) Metadata() modules.ModuleMetadata {
	return modules.ModuleMetadata{
		ID:               "auth-pam-pwquality",
		Name:             "Install PAM Password Quality",
		Description:      "Installs libpam-pwquality to enforce password complexity rules",
		Category:         "Authentication",
		DefaultRisk:      model.RiskLow,
		SupportedDistros: []string{"ubuntu"},
		Tags:             []string{"network-safe", "docker-safe"},
		CanRollback:      true,
		RequiresReboot:   false,
	}
}

func (m *Module) SupportedFindings() []string {
	return []string{"AUTH-9262"}
}

// Plan checks whether libpam-pwquality is already installed.
// Returns Applicable=false if already present.
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
		Title:       "Install PAM password quality module",
		Description: fmt.Sprintf("Install %s to enforce password complexity requirements", packageName),
		Steps:       []string{fmt.Sprintf("apt-get install -y %s", packageName)},
		Metadata:    map[string]string{"package": packageName},
		Risk:        model.RiskLow,
		CanRollback: true,
		Applicable:  true,
		Tags:        []string{"network-safe", "docker-safe"},
	}, nil
}

// Apply installs libpam-pwquality.
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

// Validate confirms libpam-pwquality is installed.
func (m *Module) Validate(ctx context.Context, _ *model.PlannedAction, inspect executor.Inspector) error {
	ok, err := inspect.IsPackageInstalled(ctx, packageName)
	if err != nil {
		return fmt.Errorf("checking %s: %w", packageName, err)
	}
	if !ok {
		return fmt.Errorf("package %s not found after apply", packageName)
	}
	return nil
}

// Rollback is a no-op (MVP conservatism — we never uninstall packages on rollback).
func (m *Module) Rollback(_ context.Context, entry *model.RollbackEntry, _ executor.Executor) error {
	switch entry.Kind {
	case model.RollbackPackage:
		return nil
	default:
		return fmt.Errorf("auth-pam-pwquality rollback: unexpected kind %q", entry.Kind)
	}
}
```

### Step 1.2 — Create test file

- [ ] Create `internal/modules/auth/pwquality/module_test.go`:

```go
package pwquality_test

import (
	"context"
	"testing"

	"github.com/maestroi/hardener/internal/model"
	"github.com/maestroi/hardener/internal/modules/auth/pwquality"
	"github.com/maestroi/hardener/internal/testhelpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPwquality_Metadata(t *testing.T) {
	m := pwquality.New()
	meta := m.Metadata()
	assert.Equal(t, "auth-pam-pwquality", meta.ID)
	assert.Contains(t, meta.Tags, "network-safe")
	assert.Contains(t, meta.Tags, "docker-safe")
	assert.True(t, meta.CanRollback)
}

func TestPwquality_SupportedFindings(t *testing.T) {
	m := pwquality.New()
	assert.Contains(t, m.SupportedFindings(), "AUTH-9262")
}

func TestPwquality_Plan_AlreadyInstalled_NotApplicable(t *testing.T) {
	inspect := &testhelpers.FakeInspector{
		InstalledPkgs: map[string]bool{"libpam-pwquality": true},
	}
	m := pwquality.New()
	finding := &model.Finding{ID: "AUTH-9262", Category: "AUTH"}

	action, err := m.Plan(context.Background(), finding, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.False(t, action.Applicable)
	assert.NotEmpty(t, action.SkipReason)
}

func TestPwquality_Plan_NotInstalled_Applicable(t *testing.T) {
	inspect := &testhelpers.FakeInspector{
		InstalledPkgs: map[string]bool{},
	}
	m := pwquality.New()
	finding := &model.Finding{ID: "AUTH-9262", Category: "AUTH"}

	action, err := m.Plan(context.Background(), finding, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.True(t, action.Applicable)
	assert.NotEmpty(t, action.Steps)
}

func TestPwquality_Apply_InstallsPackage(t *testing.T) {
	exec := &testhelpers.FakeExecutor{}
	m := pwquality.New()
	action := &model.PlannedAction{
		FindingID: "AUTH-9262",
		ModuleID:  "auth-pam-pwquality",
		Metadata:  map[string]string{"package": "libpam-pwquality"},
	}

	applied, err := m.Apply(context.Background(), action, exec)
	require.NoError(t, err)
	assert.Equal(t, model.ActionApplied, applied.Status)
	assert.True(t, exec.PackageInstalled("libpam-pwquality"))
}

func TestPwquality_Validate_Installed_NoError(t *testing.T) {
	inspect := &testhelpers.FakeInspector{
		InstalledPkgs: map[string]bool{"libpam-pwquality": true},
	}
	m := pwquality.New()
	err := m.Validate(context.Background(), &model.PlannedAction{}, inspect)
	assert.NoError(t, err)
}

func TestPwquality_Validate_NotInstalled_Error(t *testing.T) {
	inspect := &testhelpers.FakeInspector{
		InstalledPkgs: map[string]bool{},
	}
	m := pwquality.New()
	err := m.Validate(context.Background(), &model.PlannedAction{}, inspect)
	assert.Error(t, err)
}

func TestPwquality_Rollback_PackageKind_NoOp(t *testing.T) {
	exec := &testhelpers.FakeExecutor{}
	m := pwquality.New()
	entry := &model.RollbackEntry{
		Kind:        model.RollbackPackage,
		PackageName: "libpam-pwquality",
	}
	err := m.Rollback(context.Background(), entry, exec)
	assert.NoError(t, err)
}

func TestPwquality_Rollback_UnexpectedKind_Error(t *testing.T) {
	exec := &testhelpers.FakeExecutor{}
	m := pwquality.New()
	entry := &model.RollbackEntry{Kind: model.RollbackFile}
	err := m.Rollback(context.Background(), entry, exec)
	assert.Error(t, err)
}
```

### Step 1.3 — Run tests

- [ ] Run: `go test ./internal/modules/auth/pwquality/... -v`
- [ ] Expected: all 7 tests PASS, no compile errors.

### Step 1.4 — Commit

- [ ] `git add internal/modules/auth/pwquality/`
- [ ] `git commit -m "feat(auth): add AUTH-9262 PAM pwquality module"`

---

## Module 2: AUTH-9286 — Password Aging Policy

**Package:** `internal/modules/auth/passwordaging/`
**Module ID:** `auth-password-aging`
**Target file:** `/etc/login.defs`
**Risk:** RiskLow | **Tags:** `["network-safe", "docker-safe"]`

### Step 2.1 — Create testdata fixtures

- [ ] Create `testdata/auth/login.defs_default` with content:

```
# /etc/login.defs — default (unhardened)
PASS_MAX_DAYS   99999
PASS_MIN_DAYS   0
PASS_WARN_AGE   7
UMASK           022
```

- [ ] Create `testdata/auth/login.defs_hardened` with content:

```
# /etc/login.defs — hardened
PASS_MAX_DAYS   90
PASS_MIN_DAYS   1
PASS_WARN_AGE   14
UMASK           027
```

### Step 2.2 — Create module file

- [ ] Create `internal/modules/auth/passwordaging/module.go`:

```go
package passwordaging

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/maestroi/hardener/internal/executor"
	"github.com/maestroi/hardener/internal/model"
	"github.com/maestroi/hardener/internal/modules"
)

const loginDefs = "/etc/login.defs"

type policy struct {
	key   string
	value string
	re    *regexp.Regexp
}

var requiredPolicies = []policy{
	{key: "PASS_MAX_DAYS", value: "90", re: regexp.MustCompile(`(?m)^(\s*PASS_MAX_DAYS\s+)\S+`)},
	{key: "PASS_MIN_DAYS", value: "1", re: regexp.MustCompile(`(?m)^(\s*PASS_MIN_DAYS\s+)\S+`)},
	{key: "PASS_WARN_AGE", value: "14", re: regexp.MustCompile(`(?m)^(\s*PASS_WARN_AGE\s+)\S+`)},
}

// Module remediates AUTH-9286 by enforcing password aging policy in /etc/login.defs.
type Module struct{}

func New() *Module { return &Module{} }

func (m *Module) Metadata() modules.ModuleMetadata {
	return modules.ModuleMetadata{
		ID:               "auth-password-aging",
		Name:             "Password Aging Policy",
		Description:      "Sets PASS_MAX_DAYS=90, PASS_MIN_DAYS=1, PASS_WARN_AGE=14 in /etc/login.defs",
		Category:         "Authentication",
		DefaultRisk:      model.RiskLow,
		SupportedDistros: []string{"ubuntu"},
		Tags:             []string{"network-safe", "docker-safe"},
		CanRollback:      true,
		RequiresReboot:   false,
	}
}

func (m *Module) SupportedFindings() []string {
	return []string{"AUTH-9286"}
}

// missingPolicies returns the list of policies that do not match the required values.
func missingPolicies(content string) []policy {
	var missing []policy
	for _, p := range requiredPolicies {
		lineRe := regexp.MustCompile(`(?m)^` + p.key + `\s+(\S+)`)
		matches := lineRe.FindStringSubmatch(content)
		if len(matches) < 2 || strings.TrimSpace(matches[1]) != p.value {
			missing = append(missing, p)
		}
	}
	return missing
}

// applyPolicies replaces or appends each policy line in content.
func applyPolicies(content string, policies []policy) string {
	for _, p := range policies {
		replacement := p.key + "\t" + p.value
		if p.re.MatchString(content) {
			content = p.re.ReplaceAllString(content, replacement)
		} else {
			content = content + "\n" + replacement + "\n"
		}
	}
	return content
}

// Plan reads login.defs and returns applicable if any aging policy diverges.
func (m *Module) Plan(ctx context.Context, finding *model.Finding, _ *model.Profile, inspect executor.Inspector) (*model.PlannedAction, error) {
	meta := m.Metadata()

	raw, err := inspect.ReadFile(ctx, loginDefs)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", loginDefs, err)
	}

	missing := missingPolicies(string(raw))
	if len(missing) == 0 {
		return &model.PlannedAction{
			FindingID:  finding.ID,
			ModuleID:   meta.ID,
			Applicable: false,
			SkipReason: fmt.Sprintf("%s: password aging policy already meets requirements", loginDefs),
		}, nil
	}

	steps := make([]string, len(missing))
	for i, p := range missing {
		steps[i] = fmt.Sprintf("Set %s = %s in %s", p.key, p.value, loginDefs)
	}

	return &model.PlannedAction{
		FindingID:   finding.ID,
		ModuleID:    meta.ID,
		Title:       "Enforce password aging policy",
		Description: fmt.Sprintf("Set PASS_MAX_DAYS=90, PASS_MIN_DAYS=1, PASS_WARN_AGE=14 in %s", loginDefs),
		Steps:       steps,
		Metadata:    map[string]string{"target_file": loginDefs},
		Risk:        model.RiskLow,
		CanRollback: true,
		Applicable:  true,
		Tags:        []string{"network-safe", "docker-safe"},
	}, nil
}

// Apply sets the password aging policy values in login.defs.
func (m *Module) Apply(ctx context.Context, action *model.PlannedAction, exec executor.Executor) (*model.AppliedAction, error) {
	raw, err := exec.ReadFile(ctx, loginDefs)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", loginDefs, err)
	}

	missing := missingPolicies(string(raw))
	updated := applyPolicies(string(raw), missing)

	if err := exec.WriteFile(ctx, loginDefs, []byte(updated), 0644); err != nil {
		return nil, fmt.Errorf("writing %s: %w", loginDefs, err)
	}

	return &model.AppliedAction{
		PlannedAction: *action,
		AppliedAt:     time.Now(),
		Status:        model.ActionApplied,
	}, nil
}

// Validate re-reads login.defs and confirms all three policy values are present.
func (m *Module) Validate(ctx context.Context, _ *model.PlannedAction, inspect executor.Inspector) error {
	raw, err := inspect.ReadFile(ctx, loginDefs)
	if err != nil {
		return fmt.Errorf("reading %s for validation: %w", loginDefs, err)
	}
	if missing := missingPolicies(string(raw)); len(missing) > 0 {
		return fmt.Errorf("validation failed: %d aging policy value(s) still incorrect in %s", len(missing), loginDefs)
	}
	return nil
}

// Rollback restores login.defs from the backup recorded in the rollback entry.
func (m *Module) Rollback(ctx context.Context, entry *model.RollbackEntry, exec executor.Executor) error {
	if entry.Kind != model.RollbackFile {
		return fmt.Errorf("auth-password-aging rollback: unexpected kind %q", entry.Kind)
	}
	backup, err := exec.ReadFile(ctx, entry.BackupPath)
	if err != nil {
		return fmt.Errorf("reading backup at %s: %w", entry.BackupPath, err)
	}
	if err := exec.WriteFile(ctx, entry.Path, backup, entry.OrigMode); err != nil {
		return fmt.Errorf("restoring %s: %w", entry.Path, err)
	}
	return exec.SetOwner(ctx, entry.Path, entry.OrigUID, entry.OrigGID)
}
```

### Step 2.3 — Create test file

- [ ] Create `internal/modules/auth/passwordaging/module_test.go`:

```go
package passwordaging_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/maestroi/hardener/internal/model"
	"github.com/maestroi/hardener/internal/modules/auth/passwordaging"
	"github.com/maestroi/hardener/internal/testhelpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const loginDefs = "/etc/login.defs"

func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("../../../testdata/auth", name))
	require.NoError(t, err)
	return data
}

func TestPasswordAging_Metadata(t *testing.T) {
	m := passwordaging.New()
	meta := m.Metadata()
	assert.Equal(t, "auth-password-aging", meta.ID)
	assert.True(t, meta.CanRollback)
}

func TestPasswordAging_Plan_AlreadyHardened_NotApplicable(t *testing.T) {
	content := loadFixture(t, "login.defs_hardened")
	inspect := &testhelpers.FakeInspector{
		Files: map[string][]byte{loginDefs: content},
	}
	m := passwordaging.New()
	finding := &model.Finding{ID: "AUTH-9286", Category: "AUTH"}

	action, err := m.Plan(context.Background(), finding, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.False(t, action.Applicable)
	assert.NotEmpty(t, action.SkipReason)
}

func TestPasswordAging_Plan_Default_Applicable(t *testing.T) {
	content := loadFixture(t, "login.defs_default")
	inspect := &testhelpers.FakeInspector{
		Files: map[string][]byte{loginDefs: content},
	}
	m := passwordaging.New()
	finding := &model.Finding{ID: "AUTH-9286", Category: "AUTH"}

	action, err := m.Plan(context.Background(), finding, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.True(t, action.Applicable)
	assert.NotEmpty(t, action.Steps)
	assert.Equal(t, loginDefs, action.Metadata["target_file"])
}

func TestPasswordAging_Apply_WritesHardenedValues(t *testing.T) {
	content := loadFixture(t, "login.defs_default")
	exec := &testhelpers.FakeExecutor{
		FakeInspector: testhelpers.FakeInspector{
			Files: map[string][]byte{loginDefs: content},
		},
	}
	m := passwordaging.New()
	action := &model.PlannedAction{
		FindingID: "AUTH-9286",
		ModuleID:  "auth-password-aging",
		Metadata:  map[string]string{"target_file": loginDefs},
	}

	applied, err := m.Apply(context.Background(), action, exec)
	require.NoError(t, err)
	assert.Equal(t, model.ActionApplied, applied.Status)
	assert.True(t, exec.HasWritten(loginDefs))
	assert.True(t, exec.FileContains(loginDefs, "PASS_MAX_DAYS\t90"))
	assert.True(t, exec.FileContains(loginDefs, "PASS_MIN_DAYS\t1"))
	assert.True(t, exec.FileContains(loginDefs, "PASS_WARN_AGE\t14"))
}

func TestPasswordAging_Validate_HardenedContent_NoError(t *testing.T) {
	content := loadFixture(t, "login.defs_hardened")
	inspect := &testhelpers.FakeInspector{
		Files: map[string][]byte{loginDefs: content},
	}
	m := passwordaging.New()
	err := m.Validate(context.Background(), &model.PlannedAction{}, inspect)
	assert.NoError(t, err)
}

func TestPasswordAging_Validate_DefaultContent_Error(t *testing.T) {
	content := loadFixture(t, "login.defs_default")
	inspect := &testhelpers.FakeInspector{
		Files: map[string][]byte{loginDefs: content},
	}
	m := passwordaging.New()
	err := m.Validate(context.Background(), &model.PlannedAction{}, inspect)
	assert.Error(t, err)
}

func TestPasswordAging_Rollback_RestoresFile(t *testing.T) {
	original := []byte("PASS_MAX_DAYS   99999\n")
	exec := &testhelpers.FakeExecutor{
		FakeInspector: testhelpers.FakeInspector{
			Files: map[string][]byte{"/backups/login.defs.bak": original},
		},
	}
	m := passwordaging.New()
	entry := &model.RollbackEntry{
		Kind:       model.RollbackFile,
		Path:       loginDefs,
		BackupPath: "/backups/login.defs.bak",
		OrigMode:   0644,
	}

	err := m.Rollback(context.Background(), entry, exec)
	require.NoError(t, err)
	assert.True(t, exec.HasWritten(loginDefs))
}

func TestPasswordAging_Rollback_UnexpectedKind_Error(t *testing.T) {
	exec := &testhelpers.FakeExecutor{}
	m := passwordaging.New()
	entry := &model.RollbackEntry{Kind: model.RollbackPackage}
	err := m.Rollback(context.Background(), entry, exec)
	assert.Error(t, err)
}
```

### Step 2.4 — Run tests

- [ ] Run: `go test ./internal/modules/auth/passwordaging/... -v`
- [ ] Expected: all 8 tests PASS.

### Step 2.5 — Commit

- [ ] `git add internal/modules/auth/passwordaging/ testdata/auth/`
- [ ] `git commit -m "feat(auth): add AUTH-9286 password aging policy module"`

---

## Module 3: AUTH-9328 — Default Umask Policy

**Package:** `internal/modules/auth/umask/`
**Module ID:** `auth-umask`
**Target file:** `/etc/login.defs`
**Risk:** RiskLow | **Tags:** `["network-safe", "docker-safe"]`

### Step 3.1 — Create module file

- [ ] Create `internal/modules/auth/umask/module.go`:

```go
package umask

import (
	"context"
	"fmt"
	"regexp"
	"time"

	"github.com/maestroi/hardener/internal/executor"
	"github.com/maestroi/hardener/internal/model"
	"github.com/maestroi/hardener/internal/modules"
)

const (
	loginDefs    = "/etc/login.defs"
	requiredUmask = "027"
)

// activeUmaskRe matches an uncommented UMASK line with any value.
var activeUmaskRe = regexp.MustCompile(`(?m)^(\s*UMASK\s+)\S+`)

// correctUmaskRe matches an uncommented UMASK line already set to 027.
var correctUmaskRe = regexp.MustCompile(`(?m)^\s*UMASK\s+027\s*$`)

// Module remediates AUTH-9328 by setting UMASK 027 in /etc/login.defs.
type Module struct{}

func New() *Module { return &Module{} }

func (m *Module) Metadata() modules.ModuleMetadata {
	return modules.ModuleMetadata{
		ID:               "auth-umask",
		Name:             "Default Umask Policy",
		Description:      "Sets UMASK 027 in /etc/login.defs for restrictive default file permissions",
		Category:         "Authentication",
		DefaultRisk:      model.RiskLow,
		SupportedDistros: []string{"ubuntu"},
		Tags:             []string{"network-safe", "docker-safe"},
		CanRollback:      true,
		RequiresReboot:   false,
	}
}

func (m *Module) SupportedFindings() []string {
	return []string{"AUTH-9328"}
}

// Plan reads login.defs and checks whether UMASK is already set to 027.
func (m *Module) Plan(ctx context.Context, finding *model.Finding, _ *model.Profile, inspect executor.Inspector) (*model.PlannedAction, error) {
	meta := m.Metadata()

	raw, err := inspect.ReadFile(ctx, loginDefs)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", loginDefs, err)
	}

	if correctUmaskRe.Match(raw) {
		return &model.PlannedAction{
			FindingID:  finding.ID,
			ModuleID:   meta.ID,
			Applicable: false,
			SkipReason: fmt.Sprintf("%s: UMASK is already set to 027", loginDefs),
		}, nil
	}

	return &model.PlannedAction{
		FindingID:   finding.ID,
		ModuleID:    meta.ID,
		Title:       "Set default umask to 027",
		Description: fmt.Sprintf("Set UMASK 027 in %s", loginDefs),
		Steps:       []string{fmt.Sprintf("Set UMASK = 027 in %s", loginDefs)},
		Metadata:    map[string]string{"target_file": loginDefs},
		Risk:        model.RiskLow,
		CanRollback: true,
		Applicable:  true,
		Tags:        []string{"network-safe", "docker-safe"},
	}, nil
}

// Apply sets UMASK 027 in login.defs, replacing an existing line or appending.
func (m *Module) Apply(ctx context.Context, action *model.PlannedAction, exec executor.Executor) (*model.AppliedAction, error) {
	raw, err := exec.ReadFile(ctx, loginDefs)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", loginDefs, err)
	}

	content := string(raw)
	newLine := "UMASK\t\t" + requiredUmask
	if activeUmaskRe.MatchString(content) {
		content = activeUmaskRe.ReplaceAllString(content, newLine)
	} else {
		content = content + "\n" + newLine + "\n"
	}

	if err := exec.WriteFile(ctx, loginDefs, []byte(content), 0644); err != nil {
		return nil, fmt.Errorf("writing %s: %w", loginDefs, err)
	}

	return &model.AppliedAction{
		PlannedAction: *action,
		AppliedAt:     time.Now(),
		Status:        model.ActionApplied,
	}, nil
}

// Validate re-reads login.defs and confirms UMASK 027 is present.
func (m *Module) Validate(ctx context.Context, _ *model.PlannedAction, inspect executor.Inspector) error {
	raw, err := inspect.ReadFile(ctx, loginDefs)
	if err != nil {
		return fmt.Errorf("reading %s for validation: %w", loginDefs, err)
	}
	if !correctUmaskRe.Match(raw) {
		return fmt.Errorf("validation failed: UMASK 027 not found in %s", loginDefs)
	}
	return nil
}

// Rollback restores login.defs from backup.
func (m *Module) Rollback(ctx context.Context, entry *model.RollbackEntry, exec executor.Executor) error {
	if entry.Kind != model.RollbackFile {
		return fmt.Errorf("auth-umask rollback: unexpected kind %q", entry.Kind)
	}
	backup, err := exec.ReadFile(ctx, entry.BackupPath)
	if err != nil {
		return fmt.Errorf("reading backup at %s: %w", entry.BackupPath, err)
	}
	if err := exec.WriteFile(ctx, entry.Path, backup, entry.OrigMode); err != nil {
		return fmt.Errorf("restoring %s: %w", entry.Path, err)
	}
	return exec.SetOwner(ctx, entry.Path, entry.OrigUID, entry.OrigGID)
}
```

### Step 3.2 — Create test file

- [ ] Create `internal/modules/auth/umask/module_test.go`:

```go
package umask_test

import (
	"context"
	"testing"

	"github.com/maestroi/hardener/internal/model"
	"github.com/maestroi/hardener/internal/modules/auth/umask"
	"github.com/maestroi/hardener/internal/testhelpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const loginDefs = "/etc/login.defs"

func TestUmask_Metadata(t *testing.T) {
	m := umask.New()
	meta := m.Metadata()
	assert.Equal(t, "auth-umask", meta.ID)
	assert.True(t, meta.CanRollback)
}

func TestUmask_Plan_AlreadyCorrect_NotApplicable(t *testing.T) {
	content := []byte("UMASK\t\t027\n")
	inspect := &testhelpers.FakeInspector{
		Files: map[string][]byte{loginDefs: content},
	}
	m := umask.New()
	finding := &model.Finding{ID: "AUTH-9328", Category: "AUTH"}

	action, err := m.Plan(context.Background(), finding, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.False(t, action.Applicable)
	assert.NotEmpty(t, action.SkipReason)
}

func TestUmask_Plan_WrongUmask_Applicable(t *testing.T) {
	content := []byte("UMASK\t\t022\n")
	inspect := &testhelpers.FakeInspector{
		Files: map[string][]byte{loginDefs: content},
	}
	m := umask.New()
	finding := &model.Finding{ID: "AUTH-9328", Category: "AUTH"}

	action, err := m.Plan(context.Background(), finding, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.True(t, action.Applicable)
}

func TestUmask_Plan_MissingUmask_Applicable(t *testing.T) {
	content := []byte("PASS_MAX_DAYS\t90\n")
	inspect := &testhelpers.FakeInspector{
		Files: map[string][]byte{loginDefs: content},
	}
	m := umask.New()
	finding := &model.Finding{ID: "AUTH-9328", Category: "AUTH"}

	action, err := m.Plan(context.Background(), finding, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.True(t, action.Applicable)
}

func TestUmask_Apply_ReplacesExistingLine(t *testing.T) {
	content := []byte("PASS_MAX_DAYS\t90\nUMASK\t\t022\n")
	exec := &testhelpers.FakeExecutor{
		FakeInspector: testhelpers.FakeInspector{
			Files: map[string][]byte{loginDefs: content},
		},
	}
	m := umask.New()
	action := &model.PlannedAction{
		FindingID: "AUTH-9328",
		ModuleID:  "auth-umask",
		Metadata:  map[string]string{"target_file": loginDefs},
	}

	applied, err := m.Apply(context.Background(), action, exec)
	require.NoError(t, err)
	assert.Equal(t, model.ActionApplied, applied.Status)
	assert.True(t, exec.FileContains(loginDefs, "027"))
}

func TestUmask_Apply_AppendsMissingLine(t *testing.T) {
	content := []byte("PASS_MAX_DAYS\t90\n")
	exec := &testhelpers.FakeExecutor{
		FakeInspector: testhelpers.FakeInspector{
			Files: map[string][]byte{loginDefs: content},
		},
	}
	m := umask.New()
	action := &model.PlannedAction{
		FindingID: "AUTH-9328",
		ModuleID:  "auth-umask",
		Metadata:  map[string]string{"target_file": loginDefs},
	}

	applied, err := m.Apply(context.Background(), action, exec)
	require.NoError(t, err)
	assert.Equal(t, model.ActionApplied, applied.Status)
	assert.True(t, exec.FileContains(loginDefs, "027"))
}

func TestUmask_Validate_Correct_NoError(t *testing.T) {
	inspect := &testhelpers.FakeInspector{
		Files: map[string][]byte{loginDefs: []byte("UMASK\t\t027\n")},
	}
	m := umask.New()
	err := m.Validate(context.Background(), &model.PlannedAction{}, inspect)
	assert.NoError(t, err)
}

func TestUmask_Validate_Wrong_Error(t *testing.T) {
	inspect := &testhelpers.FakeInspector{
		Files: map[string][]byte{loginDefs: []byte("UMASK\t\t022\n")},
	}
	m := umask.New()
	err := m.Validate(context.Background(), &model.PlannedAction{}, inspect)
	assert.Error(t, err)
}

func TestUmask_Rollback_RestoresFile(t *testing.T) {
	original := []byte("UMASK\t\t022\n")
	exec := &testhelpers.FakeExecutor{
		FakeInspector: testhelpers.FakeInspector{
			Files: map[string][]byte{"/backups/login.defs.bak": original},
		},
	}
	m := umask.New()
	entry := &model.RollbackEntry{
		Kind:       model.RollbackFile,
		Path:       loginDefs,
		BackupPath: "/backups/login.defs.bak",
		OrigMode:   0644,
	}
	err := m.Rollback(context.Background(), entry, exec)
	require.NoError(t, err)
	assert.True(t, exec.HasWritten(loginDefs))
}
```

### Step 3.3 — Run tests

- [ ] Run: `go test ./internal/modules/auth/umask/... -v`
- [ ] Expected: all 9 tests PASS.

### Step 3.4 — Commit

- [ ] `git add internal/modules/auth/umask/`
- [ ] `git commit -m "feat(auth): add AUTH-9328 umask policy module"`

---

## Module 4: AUTH-9229 — PAM Password History

**Package:** `internal/modules/auth/pamhistory/`
**Module ID:** `auth-pam-history`
**Target file:** `/etc/pam.d/common-password`
**Risk:** RiskMedium | **Tags:** `["network-safe", "docker-safe"]`

### Step 4.1 — Create testdata fixtures

- [ ] Create `testdata/auth/common-password_default` with content:

```
# /etc/pam.d/common-password — default
password	[success=1 default=ignore]	pam_unix.so obscure sha512
password	requisite			pam_deny.so
password	required			pam_permit.so
```

- [ ] Create `testdata/auth/common-password_hardened` with content:

```
# /etc/pam.d/common-password — hardened
password	[success=1 default=ignore]	pam_unix.so obscure sha512 remember=5
password	requisite			pam_deny.so
password	required			pam_permit.so
```

### Step 4.2 — Create module file

- [ ] Create `internal/modules/auth/pamhistory/module.go`:

```go
package pamhistory

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"time"

	"github.com/maestroi/hardener/internal/executor"
	"github.com/maestroi/hardener/internal/model"
	"github.com/maestroi/hardener/internal/modules"
)

const (
	commonPassword  = "/etc/pam.d/common-password"
	minRemember     = 5
)

// pamUnixRe matches the pam_unix.so line in common-password.
var pamUnixRe = regexp.MustCompile(`(?m)^(.*pam_unix\.so.*)$`)

// rememberRe extracts the current remember= value.
var rememberRe = regexp.MustCompile(`remember=(\d+)`)

// Module remediates AUTH-9229 by adding remember=5 to the pam_unix.so line.
type Module struct{}

func New() *Module { return &Module{} }

func (m *Module) Metadata() modules.ModuleMetadata {
	return modules.ModuleMetadata{
		ID:               "auth-pam-history",
		Name:             "PAM Password History",
		Description:      "Adds remember=5 to pam_unix.so in /etc/pam.d/common-password",
		Category:         "Authentication",
		DefaultRisk:      model.RiskMedium,
		SupportedDistros: []string{"ubuntu"},
		Tags:             []string{"network-safe", "docker-safe"},
		CanRollback:      true,
		RequiresReboot:   false,
	}
}

func (m *Module) SupportedFindings() []string {
	return []string{"AUTH-9229"}
}

// needsRemember returns true when the pam_unix.so line lacks remember>= minRemember.
func needsRemember(content string) bool {
	match := pamUnixRe.FindString(content)
	if match == "" {
		return true // no pam_unix line — still applicable
	}
	sub := rememberRe.FindStringSubmatch(match)
	if len(sub) < 2 {
		return true
	}
	n, err := strconv.Atoi(sub[1])
	if err != nil {
		return true
	}
	return n < minRemember
}

// addRemember replaces or inserts remember=5 on the pam_unix.so line.
func addRemember(content string) string {
	return pamUnixRe.ReplaceAllStringFunc(content, func(line string) string {
		if rememberRe.MatchString(line) {
			return rememberRe.ReplaceAllString(line, fmt.Sprintf("remember=%d", minRemember))
		}
		return line + fmt.Sprintf(" remember=%d", minRemember)
	})
}

// Plan reads common-password and checks whether remember=5 (or higher) is present.
func (m *Module) Plan(ctx context.Context, finding *model.Finding, _ *model.Profile, inspect executor.Inspector) (*model.PlannedAction, error) {
	meta := m.Metadata()

	raw, err := inspect.ReadFile(ctx, commonPassword)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", commonPassword, err)
	}

	if !needsRemember(string(raw)) {
		return &model.PlannedAction{
			FindingID:  finding.ID,
			ModuleID:   meta.ID,
			Applicable: false,
			SkipReason: fmt.Sprintf("%s: pam_unix.so already has remember>=%d", commonPassword, minRemember),
		}, nil
	}

	return &model.PlannedAction{
		FindingID:   finding.ID,
		ModuleID:    meta.ID,
		Title:       "Enforce password history via PAM",
		Description: fmt.Sprintf("Add remember=%d to pam_unix.so in %s", minRemember, commonPassword),
		Steps:       []string{fmt.Sprintf("Add remember=%d to pam_unix.so line in %s", minRemember, commonPassword)},
		Metadata:    map[string]string{"target_file": commonPassword},
		Risk:        model.RiskMedium,
		CanRollback: true,
		Applicable:  true,
		Tags:        []string{"network-safe", "docker-safe"},
	}, nil
}

// Apply writes the updated common-password with remember=5 on the pam_unix.so line.
func (m *Module) Apply(ctx context.Context, action *model.PlannedAction, exec executor.Executor) (*model.AppliedAction, error) {
	raw, err := exec.ReadFile(ctx, commonPassword)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", commonPassword, err)
	}

	updated := addRemember(string(raw))

	if err := exec.WriteFile(ctx, commonPassword, []byte(updated), 0644); err != nil {
		return nil, fmt.Errorf("writing %s: %w", commonPassword, err)
	}

	return &model.AppliedAction{
		PlannedAction: *action,
		AppliedAt:     time.Now(),
		Status:        model.ActionApplied,
	}, nil
}

// Validate re-reads common-password and confirms remember>=5 is present.
func (m *Module) Validate(ctx context.Context, _ *model.PlannedAction, inspect executor.Inspector) error {
	raw, err := inspect.ReadFile(ctx, commonPassword)
	if err != nil {
		return fmt.Errorf("reading %s for validation: %w", commonPassword, err)
	}
	if needsRemember(string(raw)) {
		return fmt.Errorf("validation failed: remember>=%d not found in pam_unix.so line of %s", minRemember, commonPassword)
	}
	return nil
}

// Rollback restores common-password from backup.
func (m *Module) Rollback(ctx context.Context, entry *model.RollbackEntry, exec executor.Executor) error {
	if entry.Kind != model.RollbackFile {
		return fmt.Errorf("auth-pam-history rollback: unexpected kind %q", entry.Kind)
	}
	backup, err := exec.ReadFile(ctx, entry.BackupPath)
	if err != nil {
		return fmt.Errorf("reading backup at %s: %w", entry.BackupPath, err)
	}
	if err := exec.WriteFile(ctx, entry.Path, backup, entry.OrigMode); err != nil {
		return fmt.Errorf("restoring %s: %w", entry.Path, err)
	}
	return exec.SetOwner(ctx, entry.Path, entry.OrigUID, entry.OrigGID)
}
```

### Step 4.3 — Create test file

- [ ] Create `internal/modules/auth/pamhistory/module_test.go`:

```go
package pamhistory_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/maestroi/hardener/internal/model"
	"github.com/maestroi/hardener/internal/modules/auth/pamhistory"
	"github.com/maestroi/hardener/internal/testhelpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const commonPassword = "/etc/pam.d/common-password"

func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("../../../testdata/auth", name))
	require.NoError(t, err)
	return data
}

func TestPAMHistory_Metadata(t *testing.T) {
	m := pamhistory.New()
	meta := m.Metadata()
	assert.Equal(t, "auth-pam-history", meta.ID)
	assert.Equal(t, model.RiskMedium, meta.DefaultRisk)
	assert.True(t, meta.CanRollback)
}

func TestPAMHistory_Plan_AlreadyHardened_NotApplicable(t *testing.T) {
	content := loadFixture(t, "common-password_hardened")
	inspect := &testhelpers.FakeInspector{
		Files: map[string][]byte{commonPassword: content},
	}
	m := pamhistory.New()
	finding := &model.Finding{ID: "AUTH-9229", Category: "AUTH"}

	action, err := m.Plan(context.Background(), finding, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.False(t, action.Applicable)
	assert.NotEmpty(t, action.SkipReason)
}

func TestPAMHistory_Plan_Default_Applicable(t *testing.T) {
	content := loadFixture(t, "common-password_default")
	inspect := &testhelpers.FakeInspector{
		Files: map[string][]byte{commonPassword: content},
	}
	m := pamhistory.New()
	finding := &model.Finding{ID: "AUTH-9229", Category: "AUTH"}

	action, err := m.Plan(context.Background(), finding, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.True(t, action.Applicable)
	assert.Equal(t, model.RiskMedium, action.Risk)
}

func TestPAMHistory_Plan_RememberTooLow_Applicable(t *testing.T) {
	content := []byte("password\t[success=1 default=ignore]\tpam_unix.so obscure sha512 remember=3\n")
	inspect := &testhelpers.FakeInspector{
		Files: map[string][]byte{commonPassword: content},
	}
	m := pamhistory.New()
	finding := &model.Finding{ID: "AUTH-9229", Category: "AUTH"}

	action, err := m.Plan(context.Background(), finding, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.True(t, action.Applicable)
}

func TestPAMHistory_Plan_RememberHighEnough_NotApplicable(t *testing.T) {
	content := []byte("password\t[success=1 default=ignore]\tpam_unix.so obscure sha512 remember=10\n")
	inspect := &testhelpers.FakeInspector{
		Files: map[string][]byte{commonPassword: content},
	}
	m := pamhistory.New()
	finding := &model.Finding{ID: "AUTH-9229", Category: "AUTH"}

	action, err := m.Plan(context.Background(), finding, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.False(t, action.Applicable)
}

func TestPAMHistory_Apply_AddsRemember(t *testing.T) {
	content := loadFixture(t, "common-password_default")
	exec := &testhelpers.FakeExecutor{
		FakeInspector: testhelpers.FakeInspector{
			Files: map[string][]byte{commonPassword: content},
		},
	}
	m := pamhistory.New()
	action := &model.PlannedAction{
		FindingID: "AUTH-9229",
		ModuleID:  "auth-pam-history",
		Metadata:  map[string]string{"target_file": commonPassword},
	}

	applied, err := m.Apply(context.Background(), action, exec)
	require.NoError(t, err)
	assert.Equal(t, model.ActionApplied, applied.Status)
	assert.True(t, exec.FileContains(commonPassword, "remember=5"))
}

func TestPAMHistory_Validate_Hardened_NoError(t *testing.T) {
	content := loadFixture(t, "common-password_hardened")
	inspect := &testhelpers.FakeInspector{
		Files: map[string][]byte{commonPassword: content},
	}
	m := pamhistory.New()
	err := m.Validate(context.Background(), &model.PlannedAction{}, inspect)
	assert.NoError(t, err)
}

func TestPAMHistory_Validate_Default_Error(t *testing.T) {
	content := loadFixture(t, "common-password_default")
	inspect := &testhelpers.FakeInspector{
		Files: map[string][]byte{commonPassword: content},
	}
	m := pamhistory.New()
	err := m.Validate(context.Background(), &model.PlannedAction{}, inspect)
	assert.Error(t, err)
}

func TestPAMHistory_Rollback_RestoresFile(t *testing.T) {
	original := loadFixture(t, "common-password_default")
	exec := &testhelpers.FakeExecutor{
		FakeInspector: testhelpers.FakeInspector{
			Files: map[string][]byte{"/backups/common-password.bak": original},
		},
	}
	m := pamhistory.New()
	entry := &model.RollbackEntry{
		Kind:       model.RollbackFile,
		Path:       commonPassword,
		BackupPath: "/backups/common-password.bak",
		OrigMode:   0644,
	}
	err := m.Rollback(context.Background(), entry, exec)
	require.NoError(t, err)
	assert.True(t, exec.HasWritten(commonPassword))
}
```

### Step 4.4 — Run tests

- [ ] Run: `go test ./internal/modules/auth/pamhistory/... -v`
- [ ] Expected: all 9 tests PASS.

### Step 4.5 — Commit

- [ ] `git add internal/modules/auth/pamhistory/ testdata/auth/`
- [ ] `git commit -m "feat(auth): add AUTH-9229 PAM password history module"`

---

## Module 5: AUTH-9230 — Account Lockout via pam_faillock

**Package:** `internal/modules/auth/pamfaillock/`
**Module ID:** `auth-pam-faillock`
**Target file:** `/etc/security/faillock.conf`
**Risk:** RiskMedium | **Tags:** `["network-safe", "docker-safe"]`

### Step 5.1 — Create module file

- [ ] Create `internal/modules/auth/pamfaillock/module.go`:

```go
package pamfaillock

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/maestroi/hardener/internal/executor"
	"github.com/maestroi/hardener/internal/model"
	"github.com/maestroi/hardener/internal/modules"
)

const (
	faillockConf = "/etc/security/faillock.conf"
	commonAuth   = "/etc/pam.d/common-auth"
)

type faillockPolicy struct {
	key      string
	value    string
	lineRe   *regexp.Regexp
	replRe   *regexp.Regexp
}

var requiredPolicies = []faillockPolicy{
	{
		key:    "deny",
		value:  "5",
		lineRe: regexp.MustCompile(`(?m)^\s*deny\s*=\s*\S+`),
		replRe: regexp.MustCompile(`(?m)^\s*deny\s*=\s*\S+`),
	},
	{
		key:    "unlock_time",
		value:  "900",
		lineRe: regexp.MustCompile(`(?m)^\s*unlock_time\s*=\s*\S+`),
		replRe: regexp.MustCompile(`(?m)^\s*unlock_time\s*=\s*\S+`),
	},
}

// Module remediates AUTH-9230 by writing /etc/security/faillock.conf.
type Module struct{}

func New() *Module { return &Module{} }

func (m *Module) Metadata() modules.ModuleMetadata {
	return modules.ModuleMetadata{
		ID:               "auth-pam-faillock",
		Name:             "Account Lockout (pam_faillock)",
		Description:      "Configures /etc/security/faillock.conf with deny=5 and unlock_time=900",
		Category:         "Authentication",
		DefaultRisk:      model.RiskMedium,
		SupportedDistros: []string{"ubuntu"},
		Tags:             []string{"network-safe", "docker-safe"},
		CanRollback:      true,
		RequiresReboot:   false,
	}
}

func (m *Module) SupportedFindings() []string {
	return []string{"AUTH-9230"}
}

// checkPolicy reads faillock.conf content and returns which policies are missing.
func checkPolicy(content string) []faillockPolicy {
	var missing []faillockPolicy
	for _, p := range requiredPolicies {
		valueRe := regexp.MustCompile(`(?m)^\s*` + p.key + `\s*=\s*(\S+)`)
		matches := valueRe.FindStringSubmatch(content)
		if len(matches) < 2 || strings.TrimSpace(matches[1]) != p.value {
			missing = append(missing, p)
		}
	}
	return missing
}

// applyPolicy writes/updates faillock.conf content with required values.
func applyPolicy(content string, policies []faillockPolicy) string {
	for _, p := range policies {
		line := p.key + " = " + p.value
		if p.replRe.MatchString(content) {
			content = p.replRe.ReplaceAllString(content, line)
		} else {
			content = content + "\n" + line + "\n"
		}
	}
	// Ensure 'silent' is present (no value needed).
	if !regexp.MustCompile(`(?m)^\s*silent\s*$`).MatchString(content) {
		content = content + "\nsilent\n"
	}
	return content
}

// Plan reads or creates faillock.conf and returns applicable if any value is wrong.
func (m *Module) Plan(ctx context.Context, finding *model.Finding, _ *model.Profile, inspect executor.Inspector) (*model.PlannedAction, error) {
	meta := m.Metadata()

	raw, err := inspect.ReadFile(ctx, faillockConf)
	if err != nil {
		// File may not exist on some Ubuntu versions — treat as empty.
		raw = []byte{}
	}

	// Check whether common-auth already references pam_faillock.
	authRaw, authErr := inspect.ReadFile(ctx, commonAuth)
	pamFaillockPresent := authErr == nil && strings.Contains(string(authRaw), "pam_faillock")

	missing := checkPolicy(string(raw))
	if len(missing) == 0 {
		return &model.PlannedAction{
			FindingID:  finding.ID,
			ModuleID:   meta.ID,
			Applicable: false,
			SkipReason: fmt.Sprintf("%s: faillock policy already meets requirements", faillockConf),
		}, nil
	}

	steps := []string{
		fmt.Sprintf("Write deny = 5 in %s", faillockConf),
		fmt.Sprintf("Write unlock_time = 900 in %s", faillockConf),
		fmt.Sprintf("Write silent in %s", faillockConf),
	}
	if !pamFaillockPresent {
		steps = append(steps, fmt.Sprintf("MANUAL: add pam_faillock lines to %s (not automated — too risky)", commonAuth))
	}

	metadata := map[string]string{"target_file": faillockConf}
	if !pamFaillockPresent {
		metadata["manual_pam"] = "true"
	}

	return &model.PlannedAction{
		FindingID:   finding.ID,
		ModuleID:    meta.ID,
		Title:       "Configure account lockout policy",
		Description: fmt.Sprintf("Write deny=5, unlock_time=900, silent to %s", faillockConf),
		Steps:       steps,
		Metadata:    metadata,
		Risk:        model.RiskMedium,
		CanRollback: true,
		Applicable:  true,
		Tags:        []string{"network-safe", "docker-safe"},
	}, nil
}

// Apply writes faillock.conf with the required values.
// Does NOT modify /etc/pam.d/common-auth.
func (m *Module) Apply(ctx context.Context, action *model.PlannedAction, exec executor.Executor) (*model.AppliedAction, error) {
	raw, err := exec.ReadFile(ctx, faillockConf)
	if err != nil {
		raw = []byte{} // create fresh if absent
	}

	missing := checkPolicy(string(raw))
	updated := applyPolicy(string(raw), missing)

	if err := exec.WriteFile(ctx, faillockConf, []byte(updated), 0644); err != nil {
		return nil, fmt.Errorf("writing %s: %w", faillockConf, err)
	}

	return &model.AppliedAction{
		PlannedAction: *action,
		AppliedAt:     time.Now(),
		Status:        model.ActionApplied,
	}, nil
}

// Validate re-reads faillock.conf and confirms deny=5 and unlock_time=900.
func (m *Module) Validate(ctx context.Context, _ *model.PlannedAction, inspect executor.Inspector) error {
	raw, err := inspect.ReadFile(ctx, faillockConf)
	if err != nil {
		return fmt.Errorf("reading %s for validation: %w", faillockConf, err)
	}
	if missing := checkPolicy(string(raw)); len(missing) > 0 {
		return fmt.Errorf("validation failed: %d faillock policy value(s) still incorrect", len(missing))
	}
	return nil
}

// Rollback restores faillock.conf from backup.
func (m *Module) Rollback(ctx context.Context, entry *model.RollbackEntry, exec executor.Executor) error {
	if entry.Kind != model.RollbackFile {
		return fmt.Errorf("auth-pam-faillock rollback: unexpected kind %q", entry.Kind)
	}
	backup, err := exec.ReadFile(ctx, entry.BackupPath)
	if err != nil {
		return fmt.Errorf("reading backup at %s: %w", entry.BackupPath, err)
	}
	if err := exec.WriteFile(ctx, entry.Path, backup, entry.OrigMode); err != nil {
		return fmt.Errorf("restoring %s: %w", entry.Path, err)
	}
	return exec.SetOwner(ctx, entry.Path, entry.OrigUID, entry.OrigGID)
}
```

### Step 5.2 — Create test file

- [ ] Create `internal/modules/auth/pamfaillock/module_test.go`:

```go
package pamfaillock_test

import (
	"context"
	"testing"

	"github.com/maestroi/hardener/internal/model"
	"github.com/maestroi/hardener/internal/modules/auth/pamfaillock"
	"github.com/maestroi/hardener/internal/testhelpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const faillockConf = "/etc/security/faillock.conf"

func TestFaillock_Metadata(t *testing.T) {
	m := pamfaillock.New()
	meta := m.Metadata()
	assert.Equal(t, "auth-pam-faillock", meta.ID)
	assert.Equal(t, model.RiskMedium, meta.DefaultRisk)
	assert.True(t, meta.CanRollback)
}

func TestFaillock_Plan_AlreadyConfigured_NotApplicable(t *testing.T) {
	content := []byte("deny = 5\nunlock_time = 900\nsilent\n")
	inspect := &testhelpers.FakeInspector{
		Files: map[string][]byte{faillockConf: content},
	}
	m := pamfaillock.New()
	finding := &model.Finding{ID: "AUTH-9230", Category: "AUTH"}

	action, err := m.Plan(context.Background(), finding, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.False(t, action.Applicable)
	assert.NotEmpty(t, action.SkipReason)
}

func TestFaillock_Plan_MissingConf_Applicable(t *testing.T) {
	inspect := &testhelpers.FakeInspector{Files: map[string][]byte{}}
	m := pamfaillock.New()
	finding := &model.Finding{ID: "AUTH-9230", Category: "AUTH"}

	action, err := m.Plan(context.Background(), finding, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.True(t, action.Applicable)
}

func TestFaillock_Plan_NoPAMEntry_SetsManualPAMFlag(t *testing.T) {
	inspect := &testhelpers.FakeInspector{Files: map[string][]byte{}}
	m := pamfaillock.New()
	finding := &model.Finding{ID: "AUTH-9230", Category: "AUTH"}

	action, err := m.Plan(context.Background(), finding, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.Equal(t, "true", action.Metadata["manual_pam"])
}

func TestFaillock_Plan_PAMEntryPresent_NoManualFlag(t *testing.T) {
	inspect := &testhelpers.FakeInspector{
		Files: map[string][]byte{
			"/etc/pam.d/common-auth": []byte("auth required pam_faillock.so\n"),
		},
	}
	m := pamfaillock.New()
	finding := &model.Finding{ID: "AUTH-9230", Category: "AUTH"}

	action, err := m.Plan(context.Background(), finding, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.NotEqual(t, "true", action.Metadata["manual_pam"])
}

func TestFaillock_Apply_WritesPolicyValues(t *testing.T) {
	exec := &testhelpers.FakeExecutor{
		FakeInspector: testhelpers.FakeInspector{Files: map[string][]byte{}},
	}
	m := pamfaillock.New()
	action := &model.PlannedAction{
		FindingID: "AUTH-9230",
		ModuleID:  "auth-pam-faillock",
		Metadata:  map[string]string{"target_file": faillockConf},
	}

	applied, err := m.Apply(context.Background(), action, exec)
	require.NoError(t, err)
	assert.Equal(t, model.ActionApplied, applied.Status)
	assert.True(t, exec.FileContains(faillockConf, "deny = 5"))
	assert.True(t, exec.FileContains(faillockConf, "unlock_time = 900"))
	assert.True(t, exec.FileContains(faillockConf, "silent"))
}

func TestFaillock_Apply_DoesNotWriteCommonAuth(t *testing.T) {
	exec := &testhelpers.FakeExecutor{
		FakeInspector: testhelpers.FakeInspector{Files: map[string][]byte{}},
	}
	m := pamfaillock.New()
	action := &model.PlannedAction{FindingID: "AUTH-9230", ModuleID: "auth-pam-faillock"}

	_, err := m.Apply(context.Background(), action, exec)
	require.NoError(t, err)
	assert.False(t, exec.HasWritten("/etc/pam.d/common-auth"),
		"Apply must never modify common-auth automatically")
}

func TestFaillock_Validate_Correct_NoError(t *testing.T) {
	content := []byte("deny = 5\nunlock_time = 900\n")
	inspect := &testhelpers.FakeInspector{
		Files: map[string][]byte{faillockConf: content},
	}
	m := pamfaillock.New()
	err := m.Validate(context.Background(), &model.PlannedAction{}, inspect)
	assert.NoError(t, err)
}

func TestFaillock_Validate_Wrong_Error(t *testing.T) {
	content := []byte("deny = 3\nunlock_time = 600\n")
	inspect := &testhelpers.FakeInspector{
		Files: map[string][]byte{faillockConf: content},
	}
	m := pamfaillock.New()
	err := m.Validate(context.Background(), &model.PlannedAction{}, inspect)
	assert.Error(t, err)
}

func TestFaillock_Rollback_RestoresFile(t *testing.T) {
	original := []byte("# empty\n")
	exec := &testhelpers.FakeExecutor{
		FakeInspector: testhelpers.FakeInspector{
			Files: map[string][]byte{"/backups/faillock.conf.bak": original},
		},
	}
	m := pamfaillock.New()
	entry := &model.RollbackEntry{
		Kind:       model.RollbackFile,
		Path:       faillockConf,
		BackupPath: "/backups/faillock.conf.bak",
		OrigMode:   0644,
	}
	err := m.Rollback(context.Background(), entry, exec)
	require.NoError(t, err)
	assert.True(t, exec.HasWritten(faillockConf))
}
```

### Step 5.3 — Run tests

- [ ] Run: `go test ./internal/modules/auth/pamfaillock/... -v`
- [ ] Expected: all 10 tests PASS.

### Step 5.4 — Commit

- [ ] `git add internal/modules/auth/pamfaillock/`
- [ ] `git commit -m "feat(auth): add AUTH-9230 pam_faillock account lockout module"`

---

## Module 6: AUTH-9282 — Sudoers File Permissions

**Package:** `internal/modules/auth/sudoers/`
**Module ID:** `auth-sudoers-perms`
**Target file:** `/etc/sudoers`
**Risk:** RiskLow | **Tags:** `["network-safe", "docker-safe"]`

### Step 6.1 — Create module file

- [ ] Create `internal/modules/auth/sudoers/module.go`:

```go
package sudoers

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

const (
	sudoersPath  = "/etc/sudoers"
	requiredMode = fs.FileMode(0440)
)

// Module remediates AUTH-9282 by setting /etc/sudoers to mode 0440.
type Module struct{}

func New() *Module { return &Module{} }

func (m *Module) Metadata() modules.ModuleMetadata {
	return modules.ModuleMetadata{
		ID:               "auth-sudoers-perms",
		Name:             "Sudoers File Permissions",
		Description:      "Ensures /etc/sudoers is owned root:root with mode 0440",
		Category:         "Authentication",
		DefaultRisk:      model.RiskLow,
		SupportedDistros: []string{"ubuntu"},
		Tags:             []string{"network-safe", "docker-safe"},
		CanRollback:      true,
		RequiresReboot:   false,
	}
}

func (m *Module) SupportedFindings() []string {
	return []string{"AUTH-9282"}
}

// parseModeOctal parses the octal string returned by stat -c "%a".
func parseModeOctal(s string) (fs.FileMode, error) {
	s = strings.TrimSpace(s)
	n, err := strconv.ParseUint(s, 8, 32)
	if err != nil {
		return 0, fmt.Errorf("parsing mode %q: %w", s, err)
	}
	return fs.FileMode(n), nil
}

// isMorePermissive returns true when current allows bits not in required.
func isMorePermissive(current, required fs.FileMode) bool {
	return current&^required != 0
}

// Plan stats /etc/sudoers and returns applicable if mode is more permissive than 0440.
func (m *Module) Plan(ctx context.Context, finding *model.Finding, _ *model.Profile, inspect executor.Inspector) (*model.PlannedAction, error) {
	meta := m.Metadata()

	out, err := inspect.RunReadOnly(ctx, "stat", "-c", "%a", sudoersPath)
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", sudoersPath, err)
	}

	current, err := parseModeOctal(out.Stdout)
	if err != nil {
		return nil, fmt.Errorf("parsing mode of %s: %w", sudoersPath, err)
	}

	if !isMorePermissive(current, requiredMode) {
		return &model.PlannedAction{
			FindingID:  finding.ID,
			ModuleID:   meta.ID,
			Applicable: false,
			SkipReason: fmt.Sprintf("%s: mode %04o is already %04o or more restrictive", sudoersPath, current, requiredMode),
		}, nil
	}

	return &model.PlannedAction{
		FindingID:   finding.ID,
		ModuleID:    meta.ID,
		Title:       "Fix sudoers file permissions",
		Description: fmt.Sprintf("Set %s to mode %04o (currently %04o)", sudoersPath, requiredMode, current),
		Steps:       []string{fmt.Sprintf("chmod %04o %s", requiredMode, sudoersPath)},
		Metadata: map[string]string{
			"target_file":   sudoersPath,
			"current_mode":  fmt.Sprintf("%04o", current),
			"required_mode": fmt.Sprintf("%04o", requiredMode),
		},
		Risk:        model.RiskLow,
		CanRollback: true,
		Applicable:  true,
		Tags:        []string{"network-safe", "docker-safe"},
	}, nil
}

// Apply sets /etc/sudoers to mode 0440.
func (m *Module) Apply(ctx context.Context, action *model.PlannedAction, exec executor.Executor) (*model.AppliedAction, error) {
	if err := exec.SetFileMode(ctx, sudoersPath, requiredMode); err != nil {
		return nil, fmt.Errorf("setting mode on %s: %w", sudoersPath, err)
	}
	return &model.AppliedAction{
		PlannedAction: *action,
		AppliedAt:     time.Now(),
		Status:        model.ActionApplied,
	}, nil
}

// Validate re-stats /etc/sudoers and confirms mode is 440 or more restrictive.
func (m *Module) Validate(ctx context.Context, _ *model.PlannedAction, inspect executor.Inspector) error {
	out, err := inspect.RunReadOnly(ctx, "stat", "-c", "%a", sudoersPath)
	if err != nil {
		return fmt.Errorf("stat %s: %w", sudoersPath, err)
	}
	current, err := parseModeOctal(out.Stdout)
	if err != nil {
		return fmt.Errorf("parsing mode of %s: %w", sudoersPath, err)
	}
	if isMorePermissive(current, requiredMode) {
		return fmt.Errorf("validation failed: %s mode is %04o, expected %04o or more restrictive", sudoersPath, current, requiredMode)
	}
	return nil
}

// Rollback restores sudoers from backup (file content) and resets the original mode.
func (m *Module) Rollback(ctx context.Context, entry *model.RollbackEntry, exec executor.Executor) error {
	if entry.Kind != model.RollbackFile {
		return fmt.Errorf("auth-sudoers-perms rollback: unexpected kind %q", entry.Kind)
	}
	backup, err := exec.ReadFile(ctx, entry.BackupPath)
	if err != nil {
		return fmt.Errorf("reading backup at %s: %w", entry.BackupPath, err)
	}
	if err := exec.WriteFile(ctx, entry.Path, backup, entry.OrigMode); err != nil {
		return fmt.Errorf("restoring %s: %w", entry.Path, err)
	}
	return exec.SetOwner(ctx, entry.Path, entry.OrigUID, entry.OrigGID)
}
```

### Step 6.2 — Create test file

- [ ] Create `internal/modules/auth/sudoers/module_test.go`:

```go
package sudoers_test

import (
	"context"
	"testing"

	"github.com/maestroi/hardener/internal/executor"
	"github.com/maestroi/hardener/internal/model"
	"github.com/maestroi/hardener/internal/modules/auth/sudoers"
	"github.com/maestroi/hardener/internal/testhelpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const sudoersPath = "/etc/sudoers"

// fakeInspectorWithStat wraps FakeInspector and returns a configurable stat output.
type fakeInspectorWithStat struct {
	testhelpers.FakeInspector
	StatOutput string
	StatErr    error
}

func (f *fakeInspectorWithStat) RunReadOnly(_ context.Context, name string, args ...string) (executor.CmdOutput, error) {
	if name == "stat" && f.StatErr == nil {
		return executor.CmdOutput{Stdout: f.StatOutput}, nil
	}
	return executor.CmdOutput{}, f.StatErr
}

// fakeExecutorWithStat wraps FakeExecutor with configurable stat output.
type fakeExecutorWithStat struct {
	testhelpers.FakeExecutor
	StatOutput string
}

func (f *fakeExecutorWithStat) RunReadOnly(_ context.Context, name string, args ...string) (executor.CmdOutput, error) {
	if name == "stat" {
		return executor.CmdOutput{Stdout: f.StatOutput}, nil
	}
	return executor.CmdOutput{}, nil
}

func TestSudoers_Metadata(t *testing.T) {
	m := sudoers.New()
	meta := m.Metadata()
	assert.Equal(t, "auth-sudoers-perms", meta.ID)
	assert.Equal(t, model.RiskLow, meta.DefaultRisk)
	assert.True(t, meta.CanRollback)
}

func TestSudoers_Plan_AlreadyRestrictive_NotApplicable(t *testing.T) {
	inspect := &fakeInspectorWithStat{StatOutput: "440\n"}
	m := sudoers.New()
	finding := &model.Finding{ID: "AUTH-9282", Category: "AUTH"}

	action, err := m.Plan(context.Background(), finding, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.False(t, action.Applicable)
	assert.NotEmpty(t, action.SkipReason)
}

func TestSudoers_Plan_TooPermissive_Applicable(t *testing.T) {
	inspect := &fakeInspectorWithStat{StatOutput: "644\n"}
	m := sudoers.New()
	finding := &model.Finding{ID: "AUTH-9282", Category: "AUTH"}

	action, err := m.Plan(context.Background(), finding, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.True(t, action.Applicable)
	assert.Equal(t, "0644", action.Metadata["current_mode"])
	assert.Equal(t, "0440", action.Metadata["required_mode"])
}

func TestSudoers_Plan_400_NotApplicable(t *testing.T) {
	// 0400 is more restrictive than 0440 — not applicable.
	inspect := &fakeInspectorWithStat{StatOutput: "400\n"}
	m := sudoers.New()
	finding := &model.Finding{ID: "AUTH-9282", Category: "AUTH"}

	action, err := m.Plan(context.Background(), finding, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.False(t, action.Applicable)
}

func TestSudoers_Apply_SetsMode(t *testing.T) {
	exec := &testhelpers.FakeExecutor{}
	m := sudoers.New()
	action := &model.PlannedAction{
		FindingID: "AUTH-9282",
		ModuleID:  "auth-sudoers-perms",
		Metadata:  map[string]string{"target_file": sudoersPath},
	}

	applied, err := m.Apply(context.Background(), action, exec)
	require.NoError(t, err)
	assert.Equal(t, model.ActionApplied, applied.Status)
	// FakeExecutor.SetFileMode is a no-op — just confirm no error was returned.
}

func TestSudoers_Validate_CorrectMode_NoError(t *testing.T) {
	inspect := &fakeInspectorWithStat{StatOutput: "440\n"}
	m := sudoers.New()
	err := m.Validate(context.Background(), &model.PlannedAction{}, inspect)
	assert.NoError(t, err)
}

func TestSudoers_Validate_WrongMode_Error(t *testing.T) {
	inspect := &fakeInspectorWithStat{StatOutput: "644\n"}
	m := sudoers.New()
	err := m.Validate(context.Background(), &model.PlannedAction{}, inspect)
	assert.Error(t, err)
}

func TestSudoers_Rollback_RestoresFile(t *testing.T) {
	original := []byte("root ALL=(ALL:ALL) ALL\n")
	exec := &testhelpers.FakeExecutor{
		FakeInspector: testhelpers.FakeInspector{
			Files: map[string][]byte{"/backups/sudoers.bak": original},
		},
	}
	m := sudoers.New()
	entry := &model.RollbackEntry{
		Kind:       model.RollbackFile,
		Path:       sudoersPath,
		BackupPath: "/backups/sudoers.bak",
		OrigMode:   0440,
	}
	err := m.Rollback(context.Background(), entry, exec)
	require.NoError(t, err)
	assert.True(t, exec.HasWritten(sudoersPath))
}

func TestSudoers_Rollback_UnexpectedKind_Error(t *testing.T) {
	exec := &testhelpers.FakeExecutor{}
	m := sudoers.New()
	entry := &model.RollbackEntry{Kind: model.RollbackPackage}
	err := m.Rollback(context.Background(), entry, exec)
	assert.Error(t, err)
}
```

### Step 6.3 — Run tests

- [ ] Run: `go test ./internal/modules/auth/sudoers/... -v`
- [ ] Expected: all 9 tests PASS.

### Step 6.4 — Commit

- [ ] `git add internal/modules/auth/sudoers/`
- [ ] `git commit -m "feat(auth): add AUTH-9282 sudoers file permissions module"`

---

## Final Integration Step

### Step 7.1 — Run the full auth module suite

- [ ] Run: `go test ./internal/modules/auth/... -v`
- [ ] Expected: all 52 tests across all six packages PASS with zero compile errors.

### Step 7.2 — Run full repo build check

- [ ] Run: `go build ./...`
- [ ] Expected: clean exit, no errors.

### Step 7.3 — Final commit

- [ ] `git add -p` (review any outstanding changes)
- [ ] `git commit -m "feat(auth): complete group 2B authentication modules (AUTH-9229, 9230, 9262, 9282, 9286, 9328)"`

---

## File layout after completion

```
internal/modules/auth/
├── pwquality/
│   ├── module.go
│   └── module_test.go
├── passwordaging/
│   ├── module.go
│   └── module_test.go
├── umask/
│   ├── module.go
│   └── module_test.go
├── pamhistory/
│   ├── module.go
│   └── module_test.go
├── pamfaillock/
│   ├── module.go
│   └── module_test.go
└── sudoers/
    ├── module.go
    └── module_test.go

testdata/auth/
├── login.defs_default
├── login.defs_hardened
├── common-password_default
└── common-password_hardened
```

---

## Implementation notes

- `regexp.MustCompile` is used at package level for all static patterns — panics at startup if a pattern is invalid, which is the correct failure mode.
- `applyPolicies` in passwordaging and pamfaillock uses replace-then-append: if the regex matches, replace in place; otherwise append. This is safe for both fresh files and files with pre-existing (incorrect) values.
- The sudoers test wraps `FakeInspector`/`FakeExecutor` with a thin struct that overrides `RunReadOnly` to return configurable `stat` output. This is the correct approach because `FakeInspector.RunReadOnly` always returns empty `CmdOutput` — tests that need specific stat values need that override.
- `auth-pam-faillock` deliberately does not touch `/etc/pam.d/common-auth`. The PAM stack is complex and machine-specific. The module records `manual_pam = "true"` in `Metadata` so the executor layer or a human operator can surface the notice. This is noted in Steps as well.
- All rollback implementations call `SetOwner` after `WriteFile` to restore UID/GID, matching the pattern in `internal/modules/ssh/hardening.go`.
