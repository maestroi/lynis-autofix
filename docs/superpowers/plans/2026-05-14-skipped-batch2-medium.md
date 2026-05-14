# Skipped Findings — Batch 2 (Medium) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement 3 medium-risk modules covering HRDN-7222, NAME-4028, and LOGG-2190. LOGG-2190 requires `remote_syslog_server` in the profile and skips gracefully if absent.

**Architecture:** Same stateless Module interface as all other modules. Profile gets a new `RemoteSyslogServer` field. All three modules use file writes + optional service restart. Batch 1 must be completed first (test helper enhancements are required).

**Tech Stack:** Go 1.22, `github.com/maestroi/hardener`, testify.

---

## Prerequisites

Batch 1 must be merged first. The `RunReadOnlyFn` addition to `FakeInspector` is needed for HRDN-7222 tests.

---

## File Map

| File | Action | Purpose |
|------|--------|---------|
| `internal/model/profile.go` | Modify | Add `RemoteSyslogServer string` field |
| `internal/modules/hardening/compiler/module.go` | Create | HRDN-7222: chmod o-x on compiler binaries |
| `internal/modules/hardening/compiler/module_test.go` | Create | Tests for compiler |
| `internal/modules/network/dns/module.go` | Create | NAME-4028: enable DNSSEC in resolved.conf |
| `internal/modules/network/dns/module_test.go` | Create | Tests for dns |
| `internal/modules/logging/remotelog/module.go` | Create | LOGG-2190: configure rsyslog remote target |
| `internal/modules/logging/remotelog/module_test.go` | Create | Tests for remotelog |
| `internal/registry/init.go` | Modify | Register 3 new modules |
| `internal/modules/advisory/manual/module.go` | Modify | Remove HRDN-7222, NAME-4028, LOGG-2190 |

---

## Task 1: Add RemoteSyslogServer to Profile

**Files:**
- Modify: `internal/model/profile.go`

- [ ] **Step 1.1: Add field to Profile struct**

In `internal/model/profile.go`, add `RemoteSyslogServer` after `FailurePolicy`:

```go
// RemoteSyslogServer is the host:port (e.g. "10.0.0.1:514") for remote syslog.
// Required for LOGG-2190 remediation. Leave empty to skip.
RemoteSyslogServer string `yaml:"remote_syslog_server" json:"remote_syslog_server"`
```

- [ ] **Step 1.2: Run tests to confirm nothing broke**

```bash
go test ./internal/model/... -v
```

Expected: all tests pass.

- [ ] **Step 1.3: Commit**

```bash
git add internal/model/profile.go
git commit -m "feat(hardener): add RemoteSyslogServer to Profile for LOGG-2190"
```

---

## Task 2: compiler module (HRDN-7222)

**Files:**
- Create: `internal/modules/hardening/compiler/module.go`
- Create: `internal/modules/hardening/compiler/module_test.go`

The module finds gcc, cc, g++, make via `which` and removes the world-execute bit with `chmod o-x`.

- [ ] **Step 2.1: Write failing tests**

Create `internal/modules/hardening/compiler/module_test.go`:

```go
package compiler_test

import (
	"context"
	"testing"

	"github.com/maestroi/hardener/internal/executor"
	"github.com/maestroi/hardener/internal/model"
	"github.com/maestroi/hardener/internal/modules/hardening/compiler"
	"github.com/maestroi/hardener/internal/testhelpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// noneFound simulates a system with no compilers installed.
func noneFound(name string, args ...string) (executor.CmdOutput, error) {
	return executor.CmdOutput{ExitCode: 1}, nil
}

// compilerFound simulates gcc present at /usr/bin/gcc with mode 755.
func compilerFoundWith755(name string, args ...string) (executor.CmdOutput, error) {
	if name == "which" {
		return executor.CmdOutput{Stdout: "/usr/bin/" + args[0] + "\n", ExitCode: 0}, nil
	}
	// stat -c %a /usr/bin/gcc → 755
	return executor.CmdOutput{Stdout: "755\n", ExitCode: 0}, nil
}

// compilerFoundWith711 simulates gcc already restricted (711 = no world-execute for dirs, but for files this is owner-execute + execute).
// For our purposes 711 still has world-execute. Use 710 for already-restricted.
func compilerFoundAlreadyRestricted(name string, args ...string) (executor.CmdOutput, error) {
	if name == "which" {
		return executor.CmdOutput{Stdout: "/usr/bin/" + args[0] + "\n", ExitCode: 0}, nil
	}
	return executor.CmdOutput{Stdout: "710\n", ExitCode: 0}, nil
}

func TestPlan_NoCompilersInstalled(t *testing.T) {
	m := compiler.New()
	inspect := &testhelpers.FakeInspector{RunReadOnlyFn: noneFound}
	action, err := m.Plan(context.Background(), &model.Finding{ID: "HRDN-7222"}, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.False(t, action.Applicable)
	assert.NotEmpty(t, action.SkipReason)
}

func TestPlan_CompilersNeedRestricting(t *testing.T) {
	m := compiler.New()
	inspect := &testhelpers.FakeInspector{RunReadOnlyFn: compilerFoundWith755}
	action, err := m.Plan(context.Background(), &model.Finding{ID: "HRDN-7222"}, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.True(t, action.Applicable)
	assert.Equal(t, model.RiskMedium, action.Risk)
	assert.Contains(t, action.Metadata["targets"], "/usr/bin/gcc")
}

func TestApplyAndValidate(t *testing.T) {
	m := compiler.New()
	exec := &testhelpers.FakeExecutor{
		FakeInspector: testhelpers.FakeInspector{
			RunReadOnlyFn: compilerFoundWith755,
		},
	}
	action := &model.PlannedAction{
		FindingID:  "HRDN-7222",
		ModuleID:   "hardening-compiler",
		Applicable: true,
		Metadata:   map[string]string{"targets": "/usr/bin/gcc,/usr/bin/g++"},
	}

	applied, err := m.Apply(context.Background(), action, exec)
	require.NoError(t, err)
	assert.Equal(t, model.ActionApplied, applied.Status)
	assert.NotNil(t, exec.SetFileModeRecords)
}
```

- [ ] **Step 2.2: Run tests to confirm they fail**

```bash
go test ./internal/modules/hardening/compiler/... -v
```

Expected: compilation error.

- [ ] **Step 2.3: Create module**

Create `internal/modules/hardening/compiler/module.go`:

```go
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

// compilerTools are the binaries we restrict world-execute on.
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
		// Check if world-execute bit (octal 001) is set
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
		// Get current mode, then clear world-execute bit
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
```

- [ ] **Step 2.4: Run tests**

```bash
go test ./internal/modules/hardening/compiler/... -v
```

Expected: all 3 tests pass.

- [ ] **Step 2.5: Commit**

```bash
git add internal/modules/hardening/compiler/
git commit -m "feat(hardener): hardening-compiler module — HRDN-7222"
```

---

## Task 3: dns module (NAME-4028)

**Files:**
- Create: `internal/modules/network/dns/module.go`
- Create: `internal/modules/network/dns/module_test.go`

Enables `DNSSEC=yes` in `/etc/systemd/resolved.conf` and restarts `systemd-resolved`.

- [ ] **Step 3.1: Write failing tests**

Create `internal/modules/network/dns/module_test.go`:

```go
package dns_test

import (
	"context"
	"testing"

	"github.com/maestroi/hardener/internal/executor"
	"github.com/maestroi/hardener/internal/model"
	"github.com/maestroi/hardener/internal/modules/network/dns"
	"github.com/maestroi/hardener/internal/testhelpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPlan_AlreadyEnabled(t *testing.T) {
	m := dns.New()
	inspect := &testhelpers.FakeInspector{
		Files: map[string][]byte{
			dns.ResolvedConfPath: []byte("[Resolve]\nDNSSEC=yes\n"),
		},
	}
	action, err := m.Plan(context.Background(), &model.Finding{ID: "NAME-4028"}, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.False(t, action.Applicable)
}

func TestPlan_NotConfigured(t *testing.T) {
	m := dns.New()
	inspect := &testhelpers.FakeInspector{
		Files: map[string][]byte{
			dns.ResolvedConfPath: []byte("[Resolve]\n#DNSSEC=no\n"),
		},
	}
	action, err := m.Plan(context.Background(), &model.Finding{ID: "NAME-4028"}, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.True(t, action.Applicable)
	assert.Equal(t, model.RiskMedium, action.Risk)
}

func TestApplyAndValidate(t *testing.T) {
	m := dns.New()
	exec := &testhelpers.FakeExecutor{
		FakeInspector: testhelpers.FakeInspector{
			Services: map[string]executor.ServiceStatus{
				"systemd-resolved": {Name: "systemd-resolved", Active: true, Enabled: true},
			},
		},
	}
	action := &model.PlannedAction{FindingID: "NAME-4028", ModuleID: "network-dns", Applicable: true}

	applied, err := m.Apply(context.Background(), action, exec)
	require.NoError(t, err)
	assert.Equal(t, model.ActionApplied, applied.Status)
	assert.True(t, exec.FileContains(dns.ResolvedConfPath, "DNSSEC=yes"))
	assert.True(t, testhelpers.ContainsService(exec.RestartedServices, "systemd-resolved"))

	err = m.Validate(context.Background(), action, exec)
	assert.NoError(t, err)
}
```

- [ ] **Step 3.2: Run tests to confirm they fail**

```bash
go test ./internal/modules/network/dns/... -v
```

Expected: compilation error.

- [ ] **Step 3.3: Create module**

Create `internal/modules/network/dns/module.go`:

```go
package dns

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
	ResolvedConfPath = "/etc/systemd/resolved.conf"
	serviceName      = "systemd-resolved"
)

type Module struct{}

func New() *Module { return &Module{} }

func (m *Module) Metadata() modules.ModuleMetadata {
	return modules.ModuleMetadata{
		ID:               "network-dns",
		Name:             "Enable DNSSEC Validation",
		Description:      "Enables DNSSEC=yes in /etc/systemd/resolved.conf to validate DNS responses",
		Category:         "Network",
		DefaultRisk:      model.RiskMedium,
		SupportedDistros: []string{"ubuntu"},
		Tags:             []string{"network-safe"},
		CanRollback:      true,
		RequiresReboot:   false,
	}
}

func (m *Module) SupportedFindings() []string {
	return []string{"NAME-4028"}
}

func (m *Module) Plan(ctx context.Context, finding *model.Finding, _ *model.Profile, inspect executor.Inspector) (*model.PlannedAction, error) {
	meta := m.Metadata()

	content, err := inspect.ReadFile(ctx, ResolvedConfPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("network-dns: reading %s: %w", ResolvedConfPath, err)
	}

	if err == nil && strings.Contains(string(content), "DNSSEC=yes") {
		return &model.PlannedAction{
			FindingID:  finding.ID,
			ModuleID:   meta.ID,
			Applicable: false,
			SkipReason: fmt.Sprintf("%s already has DNSSEC=yes", ResolvedConfPath),
		}, nil
	}

	return &model.PlannedAction{
		FindingID:   finding.ID,
		ModuleID:    meta.ID,
		Title:       "Enable DNSSEC validation",
		Description: fmt.Sprintf("Set DNSSEC=yes in %s and restart systemd-resolved", ResolvedConfPath),
		Steps: []string{
			fmt.Sprintf("write DNSSEC=yes to %s", ResolvedConfPath),
			fmt.Sprintf("systemctl restart %s", serviceName),
		},
		Metadata:    map[string]string{"target_file": ResolvedConfPath},
		Risk:        model.RiskMedium,
		Impact:      "DNS queries will be validated via DNSSEC. Domains without valid DNSSEC records may fail to resolve.",
		CanRollback: true,
		Applicable:  true,
		Tags:        []string{"network-safe"},
	}, nil
}

func (m *Module) Apply(ctx context.Context, action *model.PlannedAction, exec executor.Executor) (*model.AppliedAction, error) {
	existing, err := exec.ReadFile(ctx, ResolvedConfPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("network-dns: reading %s: %w", ResolvedConfPath, err)
	}

	content := buildResolvedConf(string(existing))
	if err := exec.WriteFile(ctx, ResolvedConfPath, []byte(content), 0644); err != nil {
		return nil, fmt.Errorf("network-dns: writing %s: %w", ResolvedConfPath, err)
	}

	if err := exec.RestartService(ctx, serviceName); err != nil {
		return nil, fmt.Errorf("network-dns: restarting %s: %w", serviceName, err)
	}

	return &model.AppliedAction{
		PlannedAction: *action,
		AppliedAt:     time.Now(),
		Status:        model.ActionApplied,
	}, nil
}

// buildResolvedConf takes existing file content and ensures DNSSEC=yes is set
// under the [Resolve] section. If the section is absent it is added.
func buildResolvedConf(existing string) string {
	lines := strings.Split(existing, "\n")

	// Remove existing DNSSEC lines (commented or uncommented)
	var out []string
	inResolve := false
	dnssecAdded := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "[Resolve]" {
			inResolve = true
			out = append(out, line)
			out = append(out, "DNSSEC=yes")
			dnssecAdded = true
			continue
		}
		if strings.HasPrefix(trimmed, "[") && trimmed != "[Resolve]" {
			inResolve = false
		}
		if inResolve && (strings.HasPrefix(trimmed, "DNSSEC=") || strings.HasPrefix(trimmed, "#DNSSEC=")) {
			continue // skip old entry
		}
		out = append(out, line)
	}

	if !dnssecAdded {
		out = append(out, "[Resolve]", "DNSSEC=yes")
	}

	return strings.Join(out, "\n")
}

func (m *Module) Validate(ctx context.Context, _ *model.PlannedAction, inspect executor.Inspector) error {
	content, err := inspect.ReadFile(ctx, ResolvedConfPath)
	if err != nil {
		return fmt.Errorf("network-dns: reading %s: %w", ResolvedConfPath, err)
	}
	if !strings.Contains(string(content), "DNSSEC=yes") {
		return fmt.Errorf("network-dns: DNSSEC=yes not found in %s", ResolvedConfPath)
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
			return fmt.Errorf("network-dns: reading backup %s: %w", entry.BackupPath, err)
		}
		if err := exec.WriteFile(ctx, entry.Path, backup, entry.OrigMode); err != nil {
			return fmt.Errorf("network-dns: restoring %s: %w", entry.Path, err)
		}
		return exec.RestartService(ctx, serviceName)
	default:
		return fmt.Errorf("network-dns rollback: unexpected kind %q", entry.Kind)
	}
}
```

- [ ] **Step 3.4: Run tests**

```bash
go test ./internal/modules/network/dns/... -v
```

Expected: all 3 tests pass.

- [ ] **Step 3.5: Commit**

```bash
git add internal/modules/network/dns/
git commit -m "feat(hardener): network-dns module — NAME-4028"
```

---

## Task 4: remotelog module (LOGG-2190)

**Files:**
- Create: `internal/modules/logging/remotelog/module.go`
- Create: `internal/modules/logging/remotelog/module_test.go`

Writes `/etc/rsyslog.d/99-hardener-remote.conf` pointing to `profile.RemoteSyslogServer`. Skips with a profile hint if `RemoteSyslogServer` is empty.

- [ ] **Step 4.1: Write failing tests**

Create `internal/modules/logging/remotelog/module_test.go`:

```go
package remotelog_test

import (
	"context"
	"testing"

	"github.com/maestroi/hardener/internal/model"
	"github.com/maestroi/hardener/internal/modules/logging/remotelog"
	"github.com/maestroi/hardener/internal/testhelpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPlan_NoProfileConfig(t *testing.T) {
	m := remotelog.New()
	inspect := &testhelpers.FakeInspector{}
	action, err := m.Plan(context.Background(), &model.Finding{ID: "LOGG-2190"}, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.False(t, action.Applicable)
	assert.Contains(t, action.SkipReason, "remote_syslog_server")
}

func TestPlan_AlreadyConfigured(t *testing.T) {
	m := remotelog.New()
	profile := &model.Profile{RemoteSyslogServer: "10.0.0.1:514"}
	inspect := &testhelpers.FakeInspector{
		Files: map[string][]byte{
			remotelog.ConfPath: []byte("*.* @@10.0.0.1:514"),
		},
	}
	action, err := m.Plan(context.Background(), &model.Finding{ID: "LOGG-2190"}, profile, inspect)
	require.NoError(t, err)
	assert.False(t, action.Applicable)
}

func TestPlan_NeedsConfig(t *testing.T) {
	m := remotelog.New()
	profile := &model.Profile{RemoteSyslogServer: "10.0.0.1:514"}
	inspect := &testhelpers.FakeInspector{}
	action, err := m.Plan(context.Background(), &model.Finding{ID: "LOGG-2190"}, profile, inspect)
	require.NoError(t, err)
	assert.True(t, action.Applicable)
	assert.Equal(t, model.RiskMedium, action.Risk)
}

func TestApplyAndValidate(t *testing.T) {
	m := remotelog.New()
	exec := &testhelpers.FakeExecutor{}
	profile := &model.Profile{RemoteSyslogServer: "10.0.0.1:514"}
	action := &model.PlannedAction{
		FindingID:  "LOGG-2190",
		ModuleID:   "logging-remotelog",
		Applicable: true,
		Metadata:   map[string]string{"server": "10.0.0.1:514"},
	}

	applied, err := m.Apply(context.Background(), action, exec)
	require.NoError(t, err)
	assert.Equal(t, model.ActionApplied, applied.Status)
	assert.True(t, exec.FileContains(remotelog.ConfPath, "10.0.0.1:514"))
	_ = profile

	err = m.Validate(context.Background(), action, exec)
	assert.NoError(t, err)
}
```

- [ ] **Step 4.2: Run tests to confirm they fail**

```bash
go test ./internal/modules/logging/remotelog/... -v
```

Expected: compilation error.

- [ ] **Step 4.3: Create module**

Create `internal/modules/logging/remotelog/module.go`:

```go
package remotelog

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
	ConfPath    = "/etc/rsyslog.d/99-hardener-remote.conf"
	serviceName = "rsyslog"
)

type Module struct{}

func New() *Module { return &Module{} }

func (m *Module) Metadata() modules.ModuleMetadata {
	return modules.ModuleMetadata{
		ID:               "logging-remotelog",
		Name:             "Configure Remote Syslog",
		Description:      "Forwards syslog events to a remote server via rsyslog TCP transport",
		Category:         "Logging",
		DefaultRisk:      model.RiskMedium,
		SupportedDistros: []string{"ubuntu"},
		Tags:             []string{"network-safe"},
		CanRollback:      true,
		RequiresReboot:   false,
	}
}

func (m *Module) SupportedFindings() []string {
	return []string{"LOGG-2190"}
}

func (m *Module) Plan(ctx context.Context, finding *model.Finding, profile *model.Profile, inspect executor.Inspector) (*model.PlannedAction, error) {
	meta := m.Metadata()

	if profile.RemoteSyslogServer == "" {
		return &model.PlannedAction{
			FindingID:  finding.ID,
			ModuleID:   meta.ID,
			Applicable: false,
			SkipReason: "set remote_syslog_server in profile to enable LOGG-2190 remediation (e.g. \"10.0.0.1:514\")",
		}, nil
	}

	content, err := inspect.ReadFile(ctx, ConfPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("logging-remotelog: reading %s: %w", ConfPath, err)
	}

	if err == nil && strings.Contains(string(content), profile.RemoteSyslogServer) {
		return &model.PlannedAction{
			FindingID:  finding.ID,
			ModuleID:   meta.ID,
			Applicable: false,
			SkipReason: fmt.Sprintf("%s already forwards to %s", ConfPath, profile.RemoteSyslogServer),
		}, nil
	}

	return &model.PlannedAction{
		FindingID:   finding.ID,
		ModuleID:    meta.ID,
		Title:       "Configure remote syslog forwarding",
		Description: fmt.Sprintf("Forward all syslog events to %s via TCP", profile.RemoteSyslogServer),
		Steps: []string{
			fmt.Sprintf("write %s with @@%s target", ConfPath, profile.RemoteSyslogServer),
			fmt.Sprintf("systemctl restart %s", serviceName),
		},
		Metadata:    map[string]string{"server": profile.RemoteSyslogServer, "target_file": ConfPath},
		Risk:        model.RiskMedium,
		CanRollback: true,
		Applicable:  true,
		Tags:        []string{"network-safe"},
	}, nil
}

func (m *Module) Apply(ctx context.Context, action *model.PlannedAction, exec executor.Executor) (*model.AppliedAction, error) {
	server := action.Metadata["server"]
	content := fmt.Sprintf("# Managed by hardener — do not edit manually.\n*.* @@%s\n", server)

	if err := exec.WriteFile(ctx, ConfPath, []byte(content), 0644); err != nil {
		return nil, fmt.Errorf("logging-remotelog: writing %s: %w", ConfPath, err)
	}

	if err := exec.RestartService(ctx, serviceName); err != nil {
		return nil, fmt.Errorf("logging-remotelog: restarting %s: %w", serviceName, err)
	}

	return &model.AppliedAction{
		PlannedAction: *action,
		AppliedAt:     time.Now(),
		Status:        model.ActionApplied,
	}, nil
}

func (m *Module) Validate(ctx context.Context, action *model.PlannedAction, inspect executor.Inspector) error {
	server := action.Metadata["server"]
	content, err := inspect.ReadFile(ctx, ConfPath)
	if err != nil {
		return fmt.Errorf("logging-remotelog: reading %s: %w", ConfPath, err)
	}
	if !strings.Contains(string(content), server) {
		return fmt.Errorf("logging-remotelog: remote server %s not found in %s", server, ConfPath)
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
			return fmt.Errorf("logging-remotelog: reading backup %s: %w", entry.BackupPath, err)
		}
		if err := exec.WriteFile(ctx, entry.Path, backup, entry.OrigMode); err != nil {
			return fmt.Errorf("logging-remotelog: restoring %s: %w", entry.Path, err)
		}
		return exec.RestartService(ctx, serviceName)
	default:
		return fmt.Errorf("logging-remotelog rollback: unexpected kind %q", entry.Kind)
	}
}
```

- [ ] **Step 4.4: Run tests**

```bash
go test ./internal/modules/logging/remotelog/... -v
```

Expected: all 4 tests pass.

- [ ] **Step 4.5: Commit**

```bash
git add internal/modules/logging/remotelog/
git commit -m "feat(hardener): logging-remotelog module — LOGG-2190"
```

---

## Task 5: Wire up registry and clean advisory/manual

**Files:**
- Modify: `internal/registry/init.go`
- Modify: `internal/modules/advisory/manual/module.go`

- [ ] **Step 5.1: Register batch 2 modules in registry**

In `internal/registry/init.go`, add the three new imports:

```go
compilermod "github.com/maestroi/hardener/internal/modules/hardening/compiler"
dnsmod "github.com/maestroi/hardener/internal/modules/network/dns"
remotelogmod "github.com/maestroi/hardener/internal/modules/logging/remotelog"
```

Add to `Default()` after the batch 1 registrations, before `manualmod`:

```go
// Batch 2: medium modules
r.Register(compilermod.New())
r.Register(dnsmod.New())
r.Register(remotelogmod.New())
```

- [ ] **Step 5.2: Remove batch 2 finding IDs from advisory/manual**

In `internal/modules/advisory/manual/module.go`, update `supportedFindings` to remove HRDN-7222, NAME-4028, LOGG-2190. The new list is:

```go
var supportedFindings = []string{
	// Batch 3 (dangerous) — not yet implemented
	"BOOT-5122",
	"KRNL-5830",
	"FILE-6310",
	"FILE-7524",
}
```

- [ ] **Step 5.3: Run full test suite**

```bash
go test ./... -v 2>&1 | tail -40
```

Expected: all tests pass.

- [ ] **Step 5.4: Build binary**

```bash
go build ./...
```

Expected: no errors.

- [ ] **Step 5.5: Commit**

```bash
git add internal/registry/init.go internal/modules/advisory/manual/module.go
git commit -m "feat(hardener): register batch 2 modules; clean advisory/manual for HRDN-7222, NAME-4028, LOGG-2190"
```
