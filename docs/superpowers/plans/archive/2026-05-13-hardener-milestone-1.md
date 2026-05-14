# Hardener Milestone 1: Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the complete Go module foundation — all interfaces, data models, embedded profiles, config loading, Lynis report parser, and reporters — with no system mutations.

**Architecture:** Static binary, Cobra CLI, YAML profiles embedded via `go:embed`. All interfaces defined in this milestone; concrete executor and mutating implementations deferred to Milestone 2. Everything is TDD: write test first, then implement.

**Tech Stack:** Go 1.22+, `github.com/spf13/cobra@v1.8.0`, `gopkg.in/yaml.v3@v3.0.1`, `github.com/fatih/color@v1.16.0`, `github.com/olekukonko/tablewriter@v0.0.5`, `github.com/stretchr/testify@v1.9.0`

---

## File Map

```
go.mod / go.sum
main.go

cmd/root.go                          Global flags, Execute()
cmd/audit.go                         Stub — wired but unimplemented
cmd/plan.go                          Stub — wired but unimplemented
cmd/apply.go                         Stub — wired but unimplemented
cmd/rollback.go                      Stub — wired but unimplemented
cmd/report.go                        Stub — wired but unimplemented

internal/model/finding.go            Finding, Severity, CategoryFromID
internal/model/action.go             PlannedAction, AppliedAction, RiskLevel, ActionStatus
internal/model/profile.go            Profile, PortRange, SysctlPolicy, FailurePolicy
internal/model/rollback.go           RollbackManifest, RollbackEntry, RollbackKind
internal/model/run.go                Run, RunStatus

internal/executor/types.go           CmdOutput, ServiceStatus (shared value types)
internal/executor/inspector.go       Inspector interface (read-only)
internal/executor/executor.go        Executor interface (embeds Inspector, adds mutations)

internal/modules/module.go           Module interface, ModuleMetadata

internal/embedfs/profiles.go         //go:embed directive for profiles FS
internal/embedfs/profiles/server.yaml
internal/embedfs/profiles/minimal.yaml
internal/embedfs/profiles/docker-host.yaml
internal/embedfs/profiles/validator-node.example.yaml

internal/config/defaults.go          Default Config values
internal/config/loader.go            Config struct, LoadBundledProfile, LoadConfig
internal/config/merge.go             ApplyOverrides, mergeStringSlice
internal/config/validate.go          Validate(cfg) error

internal/scanner/scanner.go          Scanner interface, ScanOptions
internal/scanner/lynis/parser.go     ParseReportBytes, ScoreFromBytes, ParseReportFile
internal/scanner/lynis/runner.go     LynisScanner.Run() — stub for Milestone 1

internal/registry/registry.go        Registry struct, Register, Lookup, LookupByModuleID, All
internal/registry/init.go            Default() — empty for Milestone 1

internal/reporter/reporter.go        Reporter interface
internal/reporter/json.go            JSONReporter
internal/reporter/terminal.go        TerminalReporter

testdata/lynis-reports/basic.dat     Fixture: warnings + suggestions + score
testdata/lynis-reports/empty.dat     Fixture: no findings, score=0
testdata/lynis-reports/score-only.dat  Fixture: just hardening_index

Tests:
internal/model/finding_test.go
internal/model/action_test.go
internal/model/profile_test.go
internal/config/loader_test.go
internal/config/merge_test.go
internal/config/validate_test.go
internal/scanner/lynis/parser_test.go
internal/registry/registry_test.go
internal/reporter/json_test.go
internal/reporter/terminal_test.go
```

---

### Task 1: Initialize Go module and Cobra CLI skeleton

**Files:**
- Create: `go.mod`
- Create: `main.go`
- Create: `cmd/root.go`
- Create: `cmd/audit.go`, `cmd/plan.go`, `cmd/apply.go`, `cmd/rollback.go`, `cmd/report.go`

- [ ] **Step 1: Initialize the Go module**

```bash
cd /home/maestro/Documents/projects/lynis-autofix
go mod init github.com/maestroi/hardener
go get github.com/spf13/cobra@v1.8.0
go get gopkg.in/yaml.v3@v3.0.1
go get github.com/fatih/color@v1.16.0
go get github.com/olekukonko/tablewriter@v0.0.5
go get github.com/stretchr/testify@v1.9.0
```

- [ ] **Step 2: Create `main.go`**

```go
package main

import "github.com/maestroi/hardener/cmd"

func main() {
	cmd.Execute()
}
```

- [ ] **Step 3: Create `cmd/root.go`**

```go
package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	flagStateDir string
	flagProfile  string
	flagOutput   string
	flagConfig   string
	flagVerbose  bool
)

var rootCmd = &cobra.Command{
	Use:   "hardener",
	Short: "Linux hardening automation tool",
	Long:  "A safe, idempotent, rollback-capable Linux hardening tool powered by Lynis findings.",
}

// Execute runs the root command. Called from main().
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVar(&flagStateDir, "state-dir", "/var/lib/hardener", "state directory")
	rootCmd.PersistentFlags().StringVar(&flagProfile, "profile", "server", "profile name or path to yaml file")
	rootCmd.PersistentFlags().StringVar(&flagOutput, "output", "table", "output format: table|json")
	rootCmd.PersistentFlags().StringVar(&flagConfig, "config", "", "path to hardener.yaml")
	rootCmd.PersistentFlags().BoolVar(&flagVerbose, "verbose", false, "verbose output")
}
```

- [ ] **Step 4: Create command stubs**

```go
// cmd/audit.go
package cmd

import "github.com/spf13/cobra"

var auditFresh      bool
var auditReportPath string

var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Run Lynis and display findings + current hardening score",
	RunE: func(cmd *cobra.Command, args []string) error {
		cmd.Println("audit: not yet implemented")
		return nil
	},
}

func init() {
	auditCmd.Flags().BoolVar(&auditFresh, "fresh", false, "force a new Lynis scan")
	auditCmd.Flags().StringVar(&auditReportPath, "report-path", "", "parse a specific report file")
	rootCmd.AddCommand(auditCmd)
}
```

```go
// cmd/plan.go
package cmd

import "github.com/spf13/cobra"

var (
	planFresh    bool
	planFindings []string
	planModules  []string
)

var planCmd = &cobra.Command{
	Use:   "plan",
	Short: "Show remediation plan without applying anything",
	RunE: func(cmd *cobra.Command, args []string) error {
		cmd.Println("plan: not yet implemented")
		return nil
	},
}

func init() {
	planCmd.Flags().BoolVar(&planFresh, "fresh", false, "run Lynis scan before planning")
	planCmd.Flags().StringSliceVar(&planFindings, "finding", nil, "limit to finding IDs")
	planCmd.Flags().StringSliceVar(&planModules, "module", nil, "limit to module IDs")
	rootCmd.AddCommand(planCmd)
}
```

```go
// cmd/apply.go
package cmd

import "github.com/spf13/cobra"

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
	RunE: func(cmd *cobra.Command, args []string) error {
		cmd.Println("apply: not yet implemented")
		return nil
	},
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
```

```go
// cmd/rollback.go
package cmd

import "github.com/spf13/cobra"

var (
	rollbackRunID  string
	rollbackDryRun bool
	rollbackYes    bool
	rollbackList   bool
)

var rollbackCmd = &cobra.Command{
	Use:   "rollback",
	Short: "Reverse a previous run",
	RunE: func(cmd *cobra.Command, args []string) error {
		cmd.Println("rollback: not yet implemented")
		return nil
	},
}

func init() {
	rollbackCmd.Flags().StringVar(&rollbackRunID, "run-id", "", "run ID to roll back")
	rollbackCmd.Flags().BoolVar(&rollbackDryRun, "dry-run", false, "preview rollback without executing")
	rollbackCmd.Flags().BoolVar(&rollbackYes, "yes", false, "skip confirmation prompt")
	rollbackCmd.Flags().BoolVar(&rollbackList, "list", false, "list runs with rollback manifests")
	rootCmd.AddCommand(rollbackCmd)
}
```

```go
// cmd/report.go
package cmd

import "github.com/spf13/cobra"

var reportRunID string

var reportCmd = &cobra.Command{
	Use:   "report",
	Short: "Show run history and before/after scores",
	RunE: func(cmd *cobra.Command, args []string) error {
		cmd.Println("report: not yet implemented")
		return nil
	},
}

func init() {
	reportCmd.Flags().StringVar(&reportRunID, "run-id", "", "drill into a single run")
	rootCmd.AddCommand(reportCmd)
}
```

- [ ] **Step 5: Verify the binary compiles and help works**

```bash
go build ./...
./hardener --help
```

Expected output contains `hardener`, `audit`, `plan`, `apply`, `rollback`, `report`.

- [ ] **Step 6: Commit**

```bash
git add go.mod go.sum main.go cmd/
git commit -m "feat: initialize Go module and Cobra CLI skeleton"
```

---

### Task 2: Define model types — Finding and Action

**Files:**
- Create: `internal/model/finding.go`
- Create: `internal/model/action.go`
- Create: `internal/model/finding_test.go`
- Create: `internal/model/action_test.go`

- [ ] **Step 1: Write failing tests for Finding**

```go
// internal/model/finding_test.go
package model_test

import (
	"testing"

	"github.com/maestroi/hardener/internal/model"
	"github.com/stretchr/testify/assert"
)

func TestCategoryFromID(t *testing.T) {
	tests := []struct {
		id   string
		want string
	}{
		{"SSH-7408", "SSH"},
		{"KRNL-6000", "KRNL"},
		{"AUTH-9328", "AUTH"},
		{"FIRE-4513", "FIRE"},
		{"NOHYPHEN", "NOHYPHEN"},
		{"", "UNKNOWN"},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			assert.Equal(t, tt.want, model.CategoryFromID(tt.id))
		})
	}
}

func TestSeverity_String(t *testing.T) {
	assert.Equal(t, "info", model.SeverityInfo.String())
	assert.Equal(t, "warning", model.SeverityWarning.String())
	assert.Equal(t, "critical", model.SeverityCritical.String())
}
```

- [ ] **Step 2: Run tests — expect compile failure**

```bash
go test ./internal/model/... 2>&1 | head -20
```

Expected: `cannot find package` or `undefined: model.CategoryFromID`.

- [ ] **Step 3: Implement `internal/model/finding.go`**

```go
package model

import (
	"encoding/json"
	"strings"
)

// Severity maps to Lynis finding types.
type Severity int

const (
	SeverityInfo     Severity = iota // Lynis suggestion
	SeverityWarning                  // Lynis warning
	SeverityCritical                 // Reserved for future scanners
)

func (s Severity) String() string {
	switch s {
	case SeverityInfo:
		return "info"
	case SeverityWarning:
		return "warning"
	case SeverityCritical:
		return "critical"
	default:
		return "unknown"
	}
}

func (s Severity) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

// Finding is the normalized representation of a single Lynis finding.
type Finding struct {
	ID          string   `json:"id"`
	Category    string   `json:"category"`
	Description string   `json:"description"`
	Severity    Severity `json:"severity"`
	Details     []string `json:"details,omitempty"`
	Source      string   `json:"source"` // "lynis" | "openscap" | "custom"
	Raw         string   `json:"raw,omitempty"`
}

// CategoryFromID derives a category from the finding ID prefix.
// "SSH-7408" → "SSH", "KRNL-6000" → "KRNL".
func CategoryFromID(id string) string {
	if id == "" {
		return "UNKNOWN"
	}
	parts := strings.SplitN(id, "-", 2)
	return parts[0]
}
```

- [ ] **Step 4: Write failing tests for RiskLevel and ActionStatus**

```go
// internal/model/action_test.go
package model_test

import (
	"encoding/json"
	"testing"

	"github.com/maestroi/hardener/internal/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestRiskLevel_String(t *testing.T) {
	assert.Equal(t, "none", model.RiskNone.String())
	assert.Equal(t, "low", model.RiskLow.String())
	assert.Equal(t, "medium", model.RiskMedium.String())
	assert.Equal(t, "high", model.RiskHigh.String())
	assert.Equal(t, "critical", model.RiskCritical.String())
}

func TestRiskLevel_MarshalJSON(t *testing.T) {
	type wrapper struct {
		Risk model.RiskLevel `json:"risk"`
	}
	b, err := json.Marshal(wrapper{Risk: model.RiskHigh})
	require.NoError(t, err)
	assert.JSONEq(t, `{"risk":"high"}`, string(b))
}

func TestRiskLevel_UnmarshalYAML(t *testing.T) {
	type wrapper struct {
		Risk model.RiskLevel `yaml:"risk"`
	}
	tests := []struct {
		input string
		want  model.RiskLevel
	}{
		{"risk: none\n", model.RiskNone},
		{"risk: low\n", model.RiskLow},
		{"risk: medium\n", model.RiskMedium},
		{"risk: high\n", model.RiskHigh},
		{"risk: critical\n", model.RiskCritical},
		{"risk: HIGH\n", model.RiskHigh}, // case-insensitive
	}
	for _, tt := range tests {
		var w wrapper
		err := yaml.Unmarshal([]byte(tt.input), &w)
		require.NoError(t, err, "input: %q", tt.input)
		assert.Equal(t, tt.want, w.Risk, "input: %q", tt.input)
	}
}

func TestRiskLevel_UnmarshalYAML_InvalidValue(t *testing.T) {
	type wrapper struct {
		Risk model.RiskLevel `yaml:"risk"`
	}
	var w wrapper
	err := yaml.Unmarshal([]byte("risk: extreme\n"), &w)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "extreme")
}

func TestPlannedAction_Defaults(t *testing.T) {
	a := model.PlannedAction{
		FindingID: "SSH-7408",
		ModuleID:  "ssh-hardening",
		Applicable: true,
	}
	assert.False(t, a.Dangerous)
	assert.False(t, a.RequiresReboot)
	assert.True(t, a.Applicable)
}
```

- [ ] **Step 5: Implement `internal/model/action.go`**

```go
package model

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// RiskLevel describes how risky a remediation action is.
type RiskLevel int

const (
	RiskNone     RiskLevel = iota
	RiskLow                // config tweak, no service restart
	RiskMedium             // service restart or sysctl change
	RiskHigh               // firewall rule or kernel param
	RiskCritical           // requires --confirm-dangerous
)

func (r RiskLevel) String() string {
	switch r {
	case RiskNone:
		return "none"
	case RiskLow:
		return "low"
	case RiskMedium:
		return "medium"
	case RiskHigh:
		return "high"
	case RiskCritical:
		return "critical"
	default:
		return "unknown"
	}
}

func (r RiskLevel) MarshalJSON() ([]byte, error) {
	return json.Marshal(r.String())
}

func (r *RiskLevel) UnmarshalYAML(value interface{ Decode(interface{}) error }) error {
	var s string
	if err := value.Decode(&s); err != nil {
		return err
	}
	switch strings.ToLower(s) {
	case "", "none":
		*r = RiskNone
	case "low":
		*r = RiskLow
	case "medium":
		*r = RiskMedium
	case "high":
		*r = RiskHigh
	case "critical":
		*r = RiskCritical
	default:
		return fmt.Errorf("unknown risk level: %q (valid: none, low, medium, high, critical)", s)
	}
	return nil
}

// ActionStatus records what happened to a planned action.
type ActionStatus string

const (
	ActionPlanned      ActionStatus = "planned"
	ActionSkipped      ActionStatus = "skipped"
	ActionApplied      ActionStatus = "applied"
	ActionFailed       ActionStatus = "failed"
	ActionRolledBack   ActionStatus = "rolled_back"
	ActionNotAttempted ActionStatus = "not_attempted"
)

// PlannedAction is the output of Module.Plan() — describes what would happen.
type PlannedAction struct {
	FindingID      string            `json:"finding_id"`
	ModuleID       string            `json:"module_id"`
	Title          string            `json:"title"`
	Description    string            `json:"description"`
	Steps          []string          `json:"steps,omitempty"`
	Metadata       map[string]string `json:"metadata,omitempty"`
	Risk           RiskLevel         `json:"risk"`
	Impact         string            `json:"impact,omitempty"`
	RequiresReboot bool              `json:"requires_reboot"`
	CanRollback    bool              `json:"can_rollback"`
	Dangerous      bool              `json:"dangerous"`
	Applicable     bool              `json:"applicable"`
	SkipReason     string            `json:"skip_reason,omitempty"`
	Tags           []string          `json:"tags,omitempty"`
}

// AppliedAction embeds the plan and adds execution outcome fields.
type AppliedAction struct {
	PlannedAction
	AppliedAt    time.Time    `json:"applied_at"`
	Status       ActionStatus `json:"status"`
	Error        string       `json:"error,omitempty"`
	RollbackKeys []string     `json:"rollback_keys,omitempty"`
}
```

Note: `UnmarshalYAML` uses `gopkg.in/yaml.v3`'s node-decode pattern. The parameter type must match the v3 API. Update the signature to use `*yaml.Node` properly:

```go
// Replace the UnmarshalYAML above with the v3-correct signature:
import "gopkg.in/yaml.v3"

func (r *RiskLevel) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err != nil {
		return err
	}
	switch strings.ToLower(s) {
	case "", "none":
		*r = RiskNone
	case "low":
		*r = RiskLow
	case "medium":
		*r = RiskMedium
	case "high":
		*r = RiskHigh
	case "critical":
		*r = RiskCritical
	default:
		return fmt.Errorf("unknown risk level: %q (valid: none, low, medium, high, critical)", s)
	}
	return nil
}
```

- [ ] **Step 6: Run tests**

```bash
go test ./internal/model/... -v
```

Expected: all tests PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/model/
git commit -m "feat: add model types for Finding, RiskLevel, PlannedAction, AppliedAction"
```

---

### Task 3: Define model types — Profile, Rollback, Run

**Files:**
- Create: `internal/model/profile.go`
- Create: `internal/model/rollback.go`
- Create: `internal/model/run.go`
- Create: `internal/model/profile_test.go`

- [ ] **Step 1: Write failing tests for Profile**

```go
// internal/model/profile_test.go
package model_test

import (
	"testing"

	"github.com/maestroi/hardener/internal/model"
	"github.com/stretchr/testify/assert"
)

func TestProfile_IsModuleBlocked(t *testing.T) {
	p := model.Profile{BlockedModules: []string{"firewall-baseline", "auditd-basic"}}
	assert.True(t, p.IsModuleBlocked("firewall-baseline"))
	assert.True(t, p.IsModuleBlocked("auditd-basic"))
	assert.False(t, p.IsModuleBlocked("ssh-hardening"))
}

func TestProfile_IsModuleAllowed_EmptyListAllowsAll(t *testing.T) {
	p := model.Profile{AllowedModules: []string{}}
	assert.True(t, p.IsModuleAllowed("anything"))
}

func TestProfile_IsModuleAllowed_RestrictedList(t *testing.T) {
	p := model.Profile{AllowedModules: []string{"ssh-hardening"}}
	assert.True(t, p.IsModuleAllowed("ssh-hardening"))
	assert.False(t, p.IsModuleAllowed("auditd-basic"))
}

func TestProfile_IsPortProtected_DirectPort(t *testing.T) {
	p := model.Profile{ProtectedPorts: []int{22, 80}}
	assert.True(t, p.IsPortProtected(22, "tcp"))
	assert.True(t, p.IsPortProtected(80, "tcp"))
	assert.False(t, p.IsPortProtected(443, "tcp"))
}

func TestProfile_IsPortProtected_Range(t *testing.T) {
	p := model.Profile{
		ProtectedPortRanges: []model.PortRange{
			{Start: 9000, End: 9001, Proto: "tcp"},
		},
	}
	assert.True(t, p.IsPortProtected(9000, "tcp"))
	assert.True(t, p.IsPortProtected(9001, "tcp"))
	assert.False(t, p.IsPortProtected(9002, "tcp"))
	assert.False(t, p.IsPortProtected(9000, "udp")) // proto mismatch
}

func TestProfile_IsPortProtected_Range_BothProto(t *testing.T) {
	p := model.Profile{
		ProtectedPortRanges: []model.PortRange{
			{Start: 30303, End: 30303, Proto: "both"},
		},
	}
	assert.True(t, p.IsPortProtected(30303, "tcp"))
	assert.True(t, p.IsPortProtected(30303, "udp"))
}

func TestProfile_IsServiceProtected(t *testing.T) {
	p := model.Profile{ProtectedServices: []string{"docker", "containerd"}}
	assert.True(t, p.IsServiceProtected("docker"))
	assert.False(t, p.IsServiceProtected("ssh"))
}

func TestProfile_IsProcessProtected(t *testing.T) {
	p := model.Profile{ProtectedProcesses: []string{"lighthouse", "geth"}}
	assert.True(t, p.IsProcessProtected("lighthouse"))
	assert.False(t, p.IsProcessProtected("sshd"))
}
```

- [ ] **Step 2: Run tests — expect compile failure**

```bash
go test ./internal/model/... 2>&1 | head -10
```

- [ ] **Step 3: Implement `internal/model/profile.go`**

```go
package model

// FailurePolicy controls what happens when a module's Apply fails.
type FailurePolicy string

const (
	FailureRollbackAndStop     FailurePolicy = "rollback_failed_and_stop"
	FailureRollbackAndContinue FailurePolicy = "rollback_failed_and_continue"
	FailureRollbackEntireRun   FailurePolicy = "rollback_entire_run"
	FailureStopWithoutRollback FailurePolicy = "stop_without_rollback"
)

// PortRange defines an inclusive port range with an optional protocol constraint.
type PortRange struct {
	Start int    `yaml:"start" json:"start"`
	End   int    `yaml:"end"   json:"end"`
	Proto string `yaml:"proto" json:"proto"` // "tcp" | "udp" | "both"
}

// SysctlPolicy controls which kernel parameters hardener may modify.
type SysctlPolicy struct {
	AllowNetworkChanges bool     `yaml:"allow_network_changes" json:"allow_network_changes"`
	AllowKernelChanges  bool     `yaml:"allow_kernel_changes"  json:"allow_kernel_changes"`
	BlockedKeys         []string `yaml:"blocked_keys"          json:"blocked_keys,omitempty"`
}

// Profile is the policy document that controls what hardener may do on this system.
type Profile struct {
	Name                string        `yaml:"name"                  json:"name"`
	Description         string        `yaml:"description"           json:"description"`
	AllowedModules      []string      `yaml:"allowed_modules"       json:"allowed_modules,omitempty"`
	BlockedModules      []string      `yaml:"blocked_modules"       json:"blocked_modules,omitempty"`
	ProtectedPorts      []int         `yaml:"protected_ports"       json:"protected_ports,omitempty"`
	ProtectedPortRanges []PortRange   `yaml:"protected_port_ranges" json:"protected_port_ranges,omitempty"`
	ProtectedProcesses  []string      `yaml:"protected_processes"   json:"protected_processes,omitempty"`
	ProtectedServices   []string      `yaml:"protected_services"    json:"protected_services,omitempty"`
	MaxRiskLevel        RiskLevel     `yaml:"max_risk_level"        json:"max_risk_level"`
	RequireConfirm      []string      `yaml:"require_confirm"       json:"require_confirm,omitempty"`
	SysctlPolicy        SysctlPolicy  `yaml:"sysctl_policy"         json:"sysctl_policy"`
	FailurePolicy       FailurePolicy `yaml:"failure_policy"        json:"failure_policy"`
}

// IsModuleBlocked returns true if the module ID appears in BlockedModules.
func (p *Profile) IsModuleBlocked(moduleID string) bool {
	for _, id := range p.BlockedModules {
		if id == moduleID {
			return true
		}
	}
	return false
}

// IsModuleAllowed returns true when AllowedModules is empty (all allowed) or contains moduleID.
func (p *Profile) IsModuleAllowed(moduleID string) bool {
	if len(p.AllowedModules) == 0 {
		return true
	}
	for _, id := range p.AllowedModules {
		if id == moduleID {
			return true
		}
	}
	return false
}

// IsPortProtected returns true if port/proto matches ProtectedPorts or ProtectedPortRanges.
// Scope-aware: only blocks firewall/network/sysctl modules, not SSH config modules.
func (p *Profile) IsPortProtected(port int, proto string) bool {
	for _, pp := range p.ProtectedPorts {
		if pp == port {
			return true
		}
	}
	for _, r := range p.ProtectedPortRanges {
		if port >= r.Start && port <= r.End {
			if r.Proto == "both" || r.Proto == "" || r.Proto == proto {
				return true
			}
		}
	}
	return false
}

// IsServiceProtected returns true if the service name is in ProtectedServices.
// Scope-aware: only blocks service-disable/restart modules.
func (p *Profile) IsServiceProtected(name string) bool {
	for _, s := range p.ProtectedServices {
		if s == name {
			return true
		}
	}
	return false
}

// IsProcessProtected returns true if the process name is in ProtectedProcesses.
// Scope-aware: only blocks process-kill/restart modules.
func (p *Profile) IsProcessProtected(name string) bool {
	for _, proc := range p.ProtectedProcesses {
		if proc == name {
			return true
		}
	}
	return false
}
```

- [ ] **Step 4: Implement `internal/model/rollback.go`**

```go
package model

import (
	"io/fs"
	"time"
)

// RollbackKind identifies what kind of system state a rollback entry covers.
type RollbackKind string

const (
	RollbackFile    RollbackKind = "file"
	RollbackSysctl  RollbackKind = "sysctl"
	RollbackService RollbackKind = "service"
	RollbackPackage RollbackKind = "package"
)

// RollbackEntry records the state of one system artifact before mutation.
// Rollback engine reverses entries in descending Index order.
type RollbackEntry struct {
	Index       int          `json:"index"`
	CreatedAt   time.Time    `json:"created_at"`
	Description string       `json:"description"`
	ModuleID    string       `json:"module_id"`
	FindingID   string       `json:"finding_id"`
	Kind        RollbackKind `json:"kind"`

	// File fields
	Path       string      `json:"path,omitempty"`
	BackupPath string      `json:"backup_path,omitempty"`
	OrigMode   fs.FileMode `json:"orig_mode,omitempty"`
	OrigUID    int         `json:"orig_uid,omitempty"`
	OrigGID    int         `json:"orig_gid,omitempty"`

	// Sysctl fields
	SysctlKey   string `json:"sysctl_key,omitempty"`
	SysctlValue string `json:"sysctl_value,omitempty"`

	// Service fields
	ServiceName string `json:"service_name,omitempty"`
	WasEnabled  bool   `json:"was_enabled,omitempty"`
	WasActive   bool   `json:"was_active,omitempty"`

	// Package fields
	PackageName  string `json:"package_name,omitempty"`
	WasInstalled bool   `json:"was_installed,omitempty"`
}

// RollbackManifest is the per-run record of all pre-mutation state snapshots.
type RollbackManifest struct {
	RunID     string          `json:"run_id"`
	CreatedAt time.Time       `json:"created_at"`
	Entries   []RollbackEntry `json:"entries"`
	Complete  bool            `json:"complete"`
}
```

- [ ] **Step 5: Implement `internal/model/run.go`**

```go
package model

import "time"

// RunStatus tracks the lifecycle of an apply run.
type RunStatus string

const (
	RunPlanning   RunStatus = "planning"
	RunApplying   RunStatus = "applying"
	RunCompleted  RunStatus = "completed"
	RunFailed     RunStatus = "failed"
	RunRolledBack RunStatus = "rolled_back"
)

// Run is the index record for a single apply execution.
// Full detail lives in plan.json, applied.json, rollback.json inside the run directory.
type Run struct {
	ID            string     `json:"id"`
	StartedAt     time.Time  `json:"started_at"`
	FinishedAt    *time.Time `json:"finished_at,omitempty"`
	ProfileName   string     `json:"profile_name"`
	ScannerSource string     `json:"scanner_source"`
	StateDir      string     `json:"state_dir"`
	DryRun        bool       `json:"dry_run"`
	Status        RunStatus  `json:"status"`
	ScoreBefore   int        `json:"score_before"`
	ScoreAfter    int        `json:"score_after,omitempty"`
	OSName        string     `json:"os_name,omitempty"`
	OSVersion     string     `json:"os_version,omitempty"`
	KernelVersion string     `json:"kernel_version,omitempty"`
	Hostname      string     `json:"hostname,omitempty"`
}
```

- [ ] **Step 6: Run all model tests**

```bash
go test ./internal/model/... -v
```

Expected: all PASS including `TestProfile_IsPortProtected_*`, `TestProfile_IsServiceProtected`, etc.

- [ ] **Step 7: Commit**

```bash
git add internal/model/
git commit -m "feat: add Profile, RollbackManifest, Run model types"
```

---

### Task 4: Define Executor and Module interfaces

**Files:**
- Create: `internal/executor/types.go`
- Create: `internal/executor/inspector.go`
- Create: `internal/executor/executor.go`
- Create: `internal/modules/module.go`

These are interface-only files. No implementations yet (those are Milestone 2).

- [ ] **Step 1: Create `internal/executor/types.go`**

```go
package executor

// CmdOutput holds the result of running an external command.
type CmdOutput struct {
	Stdout   string
	Stderr   string
	ExitCode int
}

// ServiceStatus describes the current state of a systemd service.
type ServiceStatus struct {
	Name    string
	Active  bool
	Enabled bool
}
```

- [ ] **Step 2: Create `internal/executor/inspector.go`**

```go
package executor

import "context"

// Inspector provides read-only access to system state.
// Used by Module.Plan() and Module.Validate() — no mutations permitted.
type Inspector interface {
	ReadFile(ctx context.Context, path string) ([]byte, error)
	FileExists(ctx context.Context, path string) (bool, error)
	GetSysctl(ctx context.Context, key string) (string, error)
	ServiceState(ctx context.Context, name string) (ServiceStatus, error)
	IsPackageInstalled(ctx context.Context, name string) (bool, error)
	RunReadOnly(ctx context.Context, name string, args ...string) (CmdOutput, error)
}
```

- [ ] **Step 3: Create `internal/executor/executor.go`**

```go
package executor

import (
	"context"
	"io/fs"
)

// Executor extends Inspector with mutating operations.
// Used by Module.Apply() and Module.Rollback().
// LocalExecutor performs real syscalls; DryRunExecutor logs and no-ops.
type Executor interface {
	Inspector

	// Filesystem mutations
	WriteFile(ctx context.Context, path string, content []byte, mode fs.FileMode) error
	AppendFile(ctx context.Context, path string, content []byte) error
	SetFileMode(ctx context.Context, path string, mode fs.FileMode) error
	SetOwner(ctx context.Context, path string, uid, gid int) error

	// Kernel mutations
	SetSysctl(ctx context.Context, key, value string) error

	// Systemd mutations
	EnableService(ctx context.Context, name string) error
	DisableService(ctx context.Context, name string) error
	StartService(ctx context.Context, name string) error
	StopService(ctx context.Context, name string) error
	RestartService(ctx context.Context, name string) error

	// Package mutations
	InstallPackage(ctx context.Context, name string) error

	// Escape hatch for commands with no semantic method (e.g., sshd -t validation).
	Run(ctx context.Context, name string, args ...string) (CmdOutput, error)

	IsDryRun() bool
}
```

- [ ] **Step 4: Create `internal/modules/module.go`**

```go
package modules

import (
	"context"

	"github.com/maestroi/hardener/internal/executor"
	"github.com/maestroi/hardener/internal/model"
)

// ModuleMetadata describes a remediation module's identity and capabilities.
type ModuleMetadata struct {
	ID               string
	Name             string
	Description      string
	Category         string
	DefaultRisk      model.RiskLevel
	SupportedDistros []string // ["ubuntu-22.04", "ubuntu-24.04"] or ["ubuntu"]
	Tags             []string // "network-safe", "docker-safe", "validator-safe"
	CanRollback      bool
	RequiresReboot   bool
}

// Module is the interface every remediation module must implement.
// Modules are stateless — no shared state between method calls.
type Module interface {
	Metadata() ModuleMetadata
	SupportedFindings() []string

	// Plan inspects current state (read-only via Inspector) and returns what Apply would do.
	// Returns Applicable=false with SkipReason if the system already meets requirements.
	Plan(ctx context.Context, finding *model.Finding, profile *model.Profile, inspect executor.Inspector) (*model.PlannedAction, error)

	// Apply executes the remediation. Receives the PlannedAction from Plan(); module holds no state.
	Apply(ctx context.Context, action *model.PlannedAction, exec executor.Executor) (*model.AppliedAction, error)

	// Validate confirms the desired end state is present after Apply (read-only).
	Validate(ctx context.Context, action *model.PlannedAction, inspect executor.Inspector) error

	// Rollback reverses the changes described by a single RollbackEntry.
	// Called by the rollback engine, not by the module itself.
	Rollback(ctx context.Context, entry *model.RollbackEntry, exec executor.Executor) error
}
```

- [ ] **Step 5: Verify everything compiles**

```bash
go build ./...
```

Expected: no errors.

- [ ] **Step 6: Commit**

```bash
git add internal/executor/ internal/modules/
git commit -m "feat: define Executor, Inspector, and Module interfaces"
```

---

### Task 5: Embedded profiles and config loading

**Files:**
- Create: `internal/embedfs/profiles.go`
- Create: `internal/embedfs/profiles/server.yaml`
- Create: `internal/embedfs/profiles/minimal.yaml`
- Create: `internal/embedfs/profiles/docker-host.yaml`
- Create: `internal/embedfs/profiles/validator-node.example.yaml`
- Create: `internal/config/defaults.go`
- Create: `internal/config/loader.go`
- Create: `internal/config/merge.go`
- Create: `internal/config/validate.go`
- Create: `internal/config/loader_test.go`
- Create: `internal/config/merge_test.go`

- [ ] **Step 1: Create embedded profiles**

```go
// internal/embedfs/profiles.go
package embedfs

import "embed"

// Profiles is the embedded filesystem containing bundled YAML profile files.
//
//go:embed profiles
var Profiles embed.FS
```

```yaml
# internal/embedfs/profiles/server.yaml
name: server
description: "General-purpose hardening baseline for Ubuntu 22.04/24.04"

allowed_modules: []
blocked_modules: []
protected_ports: []
protected_port_ranges: []
protected_processes: []
protected_services: []

max_risk_level: high
require_confirm: []

sysctl_policy:
  allow_network_changes: true
  allow_kernel_changes: true
  blocked_keys: []

failure_policy: rollback_failed_and_stop
```

```yaml
# internal/embedfs/profiles/minimal.yaml
name: minimal
description: "Only low-risk, highly safe fixes. Suitable for production systems with no tolerance for disruption."

allowed_modules: []
blocked_modules:
  - firewall-baseline
  - kernel-sysctl
  - auditd-basic

max_risk_level: low
require_confirm:
  - ssh-hardening

sysctl_policy:
  allow_network_changes: false
  allow_kernel_changes: false
  blocked_keys: []

failure_policy: rollback_failed_and_stop
```

```yaml
# internal/embedfs/profiles/docker-host.yaml
name: docker-host
description: "For Docker hosts — preserves bridge networking and Docker-managed iptables."

blocked_modules:
  - firewall-baseline

protected_services:
  - docker
  - containerd

protected_port_ranges:
  - start: 2375
    end: 2376
    proto: tcp

sysctl_policy:
  allow_network_changes: false
  allow_kernel_changes: true
  blocked_keys:
    - net.ipv4.ip_forward

max_risk_level: high
failure_policy: rollback_failed_and_stop
```

```yaml
# internal/embedfs/profiles/validator-node.example.yaml
# Template — copy and customize for your chain. Not applied by default.
name: validator-node-example
description: "Example profile for blockchain validator/RPC nodes. Customize protected_ports and protected_processes for your chain."

protected_ports:
  - 22
protected_port_ranges:
  - start: 9000
    end: 9001
    proto: tcp
  - start: 30303
    end: 30303
    proto: both

protected_processes:
  - lighthouse
  - geth
  - erigon
  - nethermind

protected_services:
  - lighthouse
  - geth

sysctl_policy:
  allow_network_changes: false
  allow_kernel_changes: false
  blocked_keys:
    - net.ipv4.tcp_slow_start_after_idle
    - kernel.nmi_watchdog

blocked_modules:
  - auditd-basic

max_risk_level: low
failure_policy: rollback_failed_and_stop
```

- [ ] **Step 2: Write failing config loader tests**

```go
// internal/config/loader_test.go
package config_test

import (
	"testing"

	"github.com/maestroi/hardener/internal/config"
	"github.com/maestroi/hardener/internal/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadBundledProfile_Server(t *testing.T) {
	p, err := config.LoadBundledProfile("server")
	require.NoError(t, err)
	assert.Equal(t, "server", p.Name)
	assert.Equal(t, model.RiskHigh, p.MaxRiskLevel)
	assert.Equal(t, model.FailureRollbackAndStop, p.FailurePolicy)
	assert.True(t, p.SysctlPolicy.AllowNetworkChanges)
}

func TestLoadBundledProfile_Minimal(t *testing.T) {
	p, err := config.LoadBundledProfile("minimal")
	require.NoError(t, err)
	assert.Equal(t, "minimal", p.Name)
	assert.Equal(t, model.RiskLow, p.MaxRiskLevel)
	assert.Contains(t, p.BlockedModules, "firewall-baseline")
}

func TestLoadBundledProfile_DockerHost(t *testing.T) {
	p, err := config.LoadBundledProfile("docker-host")
	require.NoError(t, err)
	assert.Contains(t, p.BlockedModules, "firewall-baseline")
	assert.Contains(t, p.ProtectedServices, "docker")
	assert.False(t, p.SysctlPolicy.AllowNetworkChanges)
}

func TestLoadBundledProfile_ValidatorExample(t *testing.T) {
	p, err := config.LoadBundledProfile("validator-node.example")
	require.NoError(t, err)
	assert.Equal(t, model.RiskLow, p.MaxRiskLevel)
	assert.Contains(t, p.ProtectedProcesses, "lighthouse")
}

func TestLoadBundledProfile_Unknown(t *testing.T) {
	_, err := config.LoadBundledProfile("does-not-exist")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "does-not-exist")
}

func TestLoadConfigFromBytes_Defaults(t *testing.T) {
	cfg, err := config.LoadConfigFromBytes([]byte("version: \"1\"\n"))
	require.NoError(t, err)
	assert.Equal(t, "server", cfg.Profile)
	assert.Equal(t, "/var/lib/hardener", cfg.StateDir)
	assert.Equal(t, "table", cfg.Output)
}
```

- [ ] **Step 3: Run tests — expect compile failure**

```bash
go test ./internal/config/... 2>&1 | head -10
```

- [ ] **Step 4: Implement `internal/config/defaults.go`**

```go
package config

import "github.com/maestroi/hardener/internal/model"

// defaults returns the base Config with sensible production defaults.
func defaults() Config {
	return Config{
		Version:  "1",
		Profile:  "server",
		StateDir: "/var/lib/hardener",
		Lynis: LynisConfig{
			Binary:     "/usr/sbin/lynis",
			ReportPath: "/var/log/lynis-report.dat",
			LogPath:    "/var/log/lynis.log",
		},
		Output:           "table",
		ConfirmDangerous: false,
	}
}

// defaultProfile returns the server profile as a safe base.
func defaultProfile() *model.Profile {
	p, _ := LoadBundledProfile("server")
	return p
}
```

- [ ] **Step 5: Implement `internal/config/loader.go`**

```go
package config

import (
	"fmt"

	"gopkg.in/yaml.v3"

	"github.com/maestroi/hardener/internal/embedfs"
	"github.com/maestroi/hardener/internal/model"
)

// Config is the merged configuration from all sources.
type Config struct {
	Version          string           `yaml:"version"`
	Profile          string           `yaml:"profile"`
	StateDir         string           `yaml:"state_dir"`
	Lynis            LynisConfig      `yaml:"lynis"`
	Output           string           `yaml:"output"`
	ConfirmDangerous bool             `yaml:"confirm_dangerous"`
	ProfileOverrides ProfileOverrides `yaml:"profile_overrides"`
}

// LynisConfig holds paths and flags for the Lynis binary.
type LynisConfig struct {
	Binary     string   `yaml:"binary"`
	ReportPath string   `yaml:"report_path"`
	LogPath    string   `yaml:"log_path"`
	ExtraFlags []string `yaml:"extra_flags"`
}

// ProfileOverrides contains additive overrides applied on top of the active profile.
type ProfileOverrides struct {
	AllowedModules      []string          `yaml:"allowed_modules"`
	BlockedModules      []string          `yaml:"blocked_modules"`
	ProtectedPorts      []int             `yaml:"protected_ports"`
	ProtectedPortRanges []model.PortRange `yaml:"protected_port_ranges"`
	ProtectedProcesses  []string          `yaml:"protected_processes"`
	ProtectedServices   []string          `yaml:"protected_services"`
}

// LoadBundledProfile loads and parses a bundled YAML profile by name (e.g. "server", "docker-host").
func LoadBundledProfile(name string) (*model.Profile, error) {
	data, err := embedfs.Profiles.ReadFile("profiles/" + name + ".yaml")
	if err != nil {
		return nil, fmt.Errorf("bundled profile %q not found", name)
	}
	var p model.Profile
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("parsing profile %q: %w", name, err)
	}
	return &p, nil
}

// LoadConfigFromBytes parses a YAML config document, applying defaults for missing fields.
func LoadConfigFromBytes(data []byte) (*Config, error) {
	cfg := defaults()
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}
	return &cfg, nil
}
```

- [ ] **Step 6: Implement `internal/config/merge.go`**

```go
package config

import "github.com/maestroi/hardener/internal/model"

// ApplyOverrides merges ProfileOverrides onto a Profile copy.
// Lists are appended and deduplicated; scalars are not overridden by overlays.
func ApplyOverrides(base *model.Profile, overrides ProfileOverrides) *model.Profile {
	result := *base // shallow copy
	result.AllowedModules = mergeStringSlice(base.AllowedModules, overrides.AllowedModules)
	result.BlockedModules = mergeStringSlice(base.BlockedModules, overrides.BlockedModules)
	result.ProtectedProcesses = mergeStringSlice(base.ProtectedProcesses, overrides.ProtectedProcesses)
	result.ProtectedServices = mergeStringSlice(base.ProtectedServices, overrides.ProtectedServices)
	result.ProtectedPorts = mergeIntSlice(base.ProtectedPorts, overrides.ProtectedPorts)
	result.ProtectedPortRanges = append(base.ProtectedPortRanges, overrides.ProtectedPortRanges...)
	return &result
}

func mergeStringSlice(base, overlay []string) []string {
	seen := make(map[string]struct{}, len(base)+len(overlay))
	result := make([]string, 0, len(base)+len(overlay))
	for _, s := range append(base, overlay...) {
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			result = append(result, s)
		}
	}
	return result
}

func mergeIntSlice(base, overlay []int) []int {
	seen := make(map[int]struct{}, len(base)+len(overlay))
	result := make([]int, 0, len(base)+len(overlay))
	for _, v := range append(base, overlay...) {
		if _, ok := seen[v]; !ok {
			seen[v] = struct{}{}
			result = append(result, v)
		}
	}
	return result
}
```

- [ ] **Step 7: Implement `internal/config/validate.go`**

```go
package config

import (
	"fmt"
	"strings"
)

var validOutputFormats = map[string]bool{"table": true, "json": true}
var validFailurePolicies = map[string]bool{
	"rollback_failed_and_stop":     true,
	"rollback_failed_and_continue": true,
	"rollback_entire_run":          true,
	"stop_without_rollback":        true,
}

// Validate checks the merged Config for invalid or conflicting values.
func Validate(cfg *Config) error {
	if cfg.StateDir == "" {
		return fmt.Errorf("state_dir must not be empty")
	}
	if cfg.Profile == "" {
		return fmt.Errorf("profile must not be empty")
	}
	if !validOutputFormats[strings.ToLower(cfg.Output)] {
		return fmt.Errorf("invalid output format %q (valid: table, json)", cfg.Output)
	}
	return nil
}
```

- [ ] **Step 8: Write and run merge tests**

```go
// internal/config/merge_test.go
package config_test

import (
	"testing"

	"github.com/maestroi/hardener/internal/config"
	"github.com/maestroi/hardener/internal/model"
	"github.com/stretchr/testify/assert"
)

func TestApplyOverrides_AppendsDeduplicated(t *testing.T) {
	base := &model.Profile{
		ProtectedPorts: []int{22},
		BlockedModules: []string{"firewall-baseline"},
	}
	overrides := config.ProfileOverrides{
		ProtectedPorts: []int{22, 8080}, // 22 is a duplicate
		BlockedModules: []string{"auditd-basic"},
	}
	result := config.ApplyOverrides(base, overrides)
	assert.Equal(t, []int{22, 8080}, result.ProtectedPorts)
	assert.Equal(t, []string{"firewall-baseline", "auditd-basic"}, result.BlockedModules)
}

func TestApplyOverrides_DoesNotMutateBase(t *testing.T) {
	base := &model.Profile{ProtectedPorts: []int{22}}
	config.ApplyOverrides(base, config.ProfileOverrides{ProtectedPorts: []int{80}})
	assert.Equal(t, []int{22}, base.ProtectedPorts)
}
```

- [ ] **Step 9: Run all config tests**

```bash
go test ./internal/config/... -v
```

Expected: all PASS.

- [ ] **Step 10: Commit**

```bash
git add internal/embedfs/ internal/config/
git commit -m "feat: embed profiles and implement config loading with override support"
```

---

### Task 6: Implement Registry

**Files:**
- Create: `internal/registry/registry.go`
- Create: `internal/registry/init.go`
- Create: `internal/registry/registry_test.go`

- [ ] **Step 1: Write failing registry tests**

```go
// internal/registry/registry_test.go
package registry_test

import (
	"context"
	"testing"

	"github.com/maestroi/hardener/internal/executor"
	"github.com/maestroi/hardener/internal/model"
	"github.com/maestroi/hardener/internal/modules"
	"github.com/maestroi/hardener/internal/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubModule is a minimal Module implementation for testing.
type stubModule struct {
	meta     modules.ModuleMetadata
	findings []string
}

func (s *stubModule) Metadata() modules.ModuleMetadata { return s.meta }
func (s *stubModule) SupportedFindings() []string       { return s.findings }
func (s *stubModule) Plan(_ context.Context, _ *model.Finding, _ *model.Profile, _ executor.Inspector) (*model.PlannedAction, error) {
	return &model.PlannedAction{Applicable: true}, nil
}
func (s *stubModule) Apply(_ context.Context, _ *model.PlannedAction, _ executor.Executor) (*model.AppliedAction, error) {
	return &model.AppliedAction{}, nil
}
func (s *stubModule) Validate(_ context.Context, _ *model.PlannedAction, _ executor.Inspector) error {
	return nil
}
func (s *stubModule) Rollback(_ context.Context, _ *model.RollbackEntry, _ executor.Executor) error {
	return nil
}

func TestRegistry_LookupMiss(t *testing.T) {
	r := registry.New()
	_, ok := r.Lookup("UNKNOWN-0000")
	assert.False(t, ok)
}

func TestRegistry_RegisterAndLookupByFinding(t *testing.T) {
	r := registry.New()
	m := &stubModule{
		meta:     modules.ModuleMetadata{ID: "ssh-hardening"},
		findings: []string{"SSH-7408", "SSH-7902"},
	}
	r.Register(m)

	got, ok := r.Lookup("SSH-7408")
	require.True(t, ok)
	assert.Equal(t, "ssh-hardening", got.Metadata().ID)

	got2, ok2 := r.Lookup("SSH-7902")
	require.True(t, ok2)
	assert.Equal(t, "ssh-hardening", got2.Metadata().ID)
}

func TestRegistry_LookupByModuleID(t *testing.T) {
	r := registry.New()
	m := &stubModule{
		meta:     modules.ModuleMetadata{ID: "ssh-hardening"},
		findings: []string{"SSH-7408"},
	}
	r.Register(m)

	got, ok := r.LookupByModuleID("ssh-hardening")
	require.True(t, ok)
	assert.Equal(t, "ssh-hardening", got.Metadata().ID)

	_, ok2 := r.LookupByModuleID("does-not-exist")
	assert.False(t, ok2)
}

func TestRegistry_All_NoDuplicates(t *testing.T) {
	r := registry.New()
	m := &stubModule{
		meta:     modules.ModuleMetadata{ID: "ssh-hardening"},
		findings: []string{"SSH-7408", "SSH-7902"},
	}
	r.Register(m)
	all := r.All()
	assert.Len(t, all, 1) // one module, two findings — All() returns distinct modules
}

func TestRegistry_Default_IsEmpty(t *testing.T) {
	r := registry.Default()
	assert.Empty(t, r.All()) // no modules in Milestone 1
}
```

- [ ] **Step 2: Run tests — expect compile failure**

```bash
go test ./internal/registry/... 2>&1 | head -10
```

- [ ] **Step 3: Implement `internal/registry/registry.go`**

```go
package registry

import "github.com/maestroi/hardener/internal/modules"

// Registry maps finding IDs and module IDs to Module implementations.
type Registry struct {
	byFinding map[string]modules.Module
	byModule  map[string]modules.Module
}

// New returns an empty Registry.
func New() *Registry {
	return &Registry{
		byFinding: make(map[string]modules.Module),
		byModule:  make(map[string]modules.Module),
	}
}

// Register adds a module to the registry, indexing it by all its supported finding IDs.
func (r *Registry) Register(m modules.Module) {
	r.byModule[m.Metadata().ID] = m
	for _, id := range m.SupportedFindings() {
		r.byFinding[id] = m
	}
}

// Lookup returns the module registered for a given finding ID.
func (r *Registry) Lookup(findingID string) (modules.Module, bool) {
	m, ok := r.byFinding[findingID]
	return m, ok
}

// LookupByModuleID returns a module by its module ID.
func (r *Registry) LookupByModuleID(moduleID string) (modules.Module, bool) {
	m, ok := r.byModule[moduleID]
	return m, ok
}

// All returns all registered modules without duplicates.
func (r *Registry) All() []modules.Module {
	seen := make(map[string]bool, len(r.byModule))
	result := make([]modules.Module, 0, len(r.byModule))
	for _, m := range r.byFinding {
		id := m.Metadata().ID
		if !seen[id] {
			seen[id] = true
			result = append(result, m)
		}
	}
	return result
}
```

- [ ] **Step 4: Implement `internal/registry/init.go`**

```go
package registry

// Default returns the production registry with all bundled modules registered.
// In Milestone 1, no concrete modules exist yet — returns an empty registry.
// Modules are added in Milestone 3.
func Default() *Registry {
	return New()
}
```

- [ ] **Step 5: Run registry tests**

```bash
go test ./internal/registry/... -v
```

Expected: all PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/registry/
git commit -m "feat: implement module registry with finding and module ID lookup"
```

---

### Task 7: Lynis report parser

**Files:**
- Create: `testdata/lynis-reports/basic.dat`
- Create: `testdata/lynis-reports/empty.dat`
- Create: `testdata/lynis-reports/score-only.dat`
- Create: `internal/scanner/scanner.go`
- Create: `internal/scanner/lynis/parser.go`
- Create: `internal/scanner/lynis/runner.go`
- Create: `internal/scanner/lynis/parser_test.go`

- [ ] **Step 1: Create report fixtures**

```
# testdata/lynis-reports/basic.dat
report_version_major=1
report_version_minor=2
lynis_version=3.0.9

warning[]=SSH-7408|sshd option PermitRootLogin is not disabled|
warning[]=AUTH-9262|No password set for single user mode|extra detail here
suggestion[]=KRNL-6000|One or more sysctl values differ from the scan profile and could be tweaked.|
suggestion[]=FIRE-4513|Check iptables rules to see which rules are currently not used|
suggestion[]=PKGS-7394|Install debsums utility to periodically verify installed packages.|

hardening_index=62
```

```
# testdata/lynis-reports/empty.dat
report_version_major=1
lynis_version=3.0.9
hardening_index=0
```

```
# testdata/lynis-reports/score-only.dat
hardening_index=81
```

- [ ] **Step 2: Write failing parser tests**

```go
// internal/scanner/lynis/parser_test.go
package lynis_test

import (
	"os"
	"testing"

	"github.com/maestroi/hardener/internal/model"
	"github.com/maestroi/hardener/internal/scanner/lynis"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseReportBytes_Warnings(t *testing.T) {
	data, err := os.ReadFile("../../../testdata/lynis-reports/basic.dat")
	require.NoError(t, err)

	findings, err := lynis.ParseReportBytes(data)
	require.NoError(t, err)

	var warnings []*model.Finding
	for _, f := range findings {
		if f.Severity == model.SeverityWarning {
			warnings = append(warnings, f)
		}
	}
	require.Len(t, warnings, 2)
	assert.Equal(t, "SSH-7408", warnings[0].ID)
	assert.Equal(t, "SSH", warnings[0].Category)
	assert.Equal(t, "sshd option PermitRootLogin is not disabled", warnings[0].Description)
	assert.Equal(t, model.SeverityWarning, warnings[0].Severity)
	assert.Equal(t, "lynis", warnings[0].Source)
}

func TestParseReportBytes_Suggestions(t *testing.T) {
	data, err := os.ReadFile("../../../testdata/lynis-reports/basic.dat")
	require.NoError(t, err)

	findings, err := lynis.ParseReportBytes(data)
	require.NoError(t, err)

	var suggestions []*model.Finding
	for _, f := range findings {
		if f.Severity == model.SeverityInfo {
			suggestions = append(suggestions, f)
		}
	}
	assert.Len(t, suggestions, 3)
	ids := make([]string, len(suggestions))
	for i, s := range suggestions {
		ids[i] = s.ID
	}
	assert.Contains(t, ids, "KRNL-6000")
	assert.Contains(t, ids, "FIRE-4513")
}

func TestParseReportBytes_DetailsInThirdField(t *testing.T) {
	data, err := os.ReadFile("../../../testdata/lynis-reports/basic.dat")
	require.NoError(t, err)

	findings, err := lynis.ParseReportBytes(data)
	require.NoError(t, err)

	var auth9262 *model.Finding
	for _, f := range findings {
		if f.ID == "AUTH-9262" {
			auth9262 = f
			break
		}
	}
	require.NotNil(t, auth9262)
	assert.Contains(t, auth9262.Details, "extra detail here")
}

func TestParseReportBytes_Empty(t *testing.T) {
	data, err := os.ReadFile("../../../testdata/lynis-reports/empty.dat")
	require.NoError(t, err)

	findings, err := lynis.ParseReportBytes(data)
	require.NoError(t, err)
	assert.Empty(t, findings)
}

func TestScoreFromBytes_BasicReport(t *testing.T) {
	data, err := os.ReadFile("../../../testdata/lynis-reports/basic.dat")
	require.NoError(t, err)

	score, err := lynis.ScoreFromBytes(data)
	require.NoError(t, err)
	assert.Equal(t, 62, score)
}

func TestScoreFromBytes_ScoreOnly(t *testing.T) {
	data, err := os.ReadFile("../../../testdata/lynis-reports/score-only.dat")
	require.NoError(t, err)

	score, err := lynis.ScoreFromBytes(data)
	require.NoError(t, err)
	assert.Equal(t, 81, score)
}

func TestScoreFromBytes_NoScore_ReturnsZero(t *testing.T) {
	score, err := lynis.ScoreFromBytes([]byte("warning[]=SSH-7408|desc|\n"))
	require.NoError(t, err)
	assert.Equal(t, 0, score)
}
```

- [ ] **Step 3: Run tests — expect compile failure**

```bash
go test ./internal/scanner/... 2>&1 | head -10
```

- [ ] **Step 4: Create `internal/scanner/scanner.go`**

```go
package scanner

import (
	"context"

	"github.com/maestroi/hardener/internal/model"
)

// ScanOptions configures a Lynis scan run.
type ScanOptions struct {
	ReportPath string
	LogPath    string
	ExtraFlags []string
}

// Scanner produces Findings from an audit tool.
type Scanner interface {
	Run(ctx context.Context, opts ScanOptions) error
	ParseReport(ctx context.Context, path string) ([]*model.Finding, error)
	Score(ctx context.Context, path string) (int, error)
}
```

- [ ] **Step 5: Implement `internal/scanner/lynis/parser.go`**

```go
package lynis

import (
	"bufio"
	"bytes"
	"fmt"
	"strconv"
	"strings"

	"github.com/maestroi/hardener/internal/model"
)

// ParseReportBytes parses a Lynis report (lynis-report.dat) from raw bytes.
func ParseReportBytes(data []byte) ([]*model.Finding, error) {
	var findings []*model.Finding
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if f := parseWarningLine(line); f != nil {
			findings = append(findings, f)
			continue
		}
		if f := parseSuggestionLine(line); f != nil {
			findings = append(findings, f)
		}
	}
	return findings, scanner.Err()
}

// ScoreFromBytes extracts the hardening_index value from a Lynis report.
// Returns 0 if no score line is found.
func ScoreFromBytes(data []byte) (int, error) {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "hardening_index=") {
			continue
		}
		val := strings.TrimPrefix(line, "hardening_index=")
		n, err := strconv.Atoi(strings.TrimSpace(val))
		if err != nil {
			return 0, fmt.Errorf("invalid hardening_index value %q: %w", val, err)
		}
		return n, nil
	}
	return 0, scanner.Err()
}

// parseWarningLine parses a line like: warning[]=SSH-7408|description|details
func parseWarningLine(line string) *model.Finding {
	const prefix = "warning[]="
	if !strings.HasPrefix(line, prefix) {
		return nil
	}
	return parseFindingLine(strings.TrimPrefix(line, prefix), model.SeverityWarning, line)
}

// parseSuggestionLine parses a line like: suggestion[]=KRNL-6000|description|details
func parseSuggestionLine(line string) *model.Finding {
	const prefix = "suggestion[]="
	if !strings.HasPrefix(line, prefix) {
		return nil
	}
	return parseFindingLine(strings.TrimPrefix(line, prefix), model.SeverityInfo, line)
}

func parseFindingLine(value string, severity model.Severity, raw string) *model.Finding {
	parts := strings.SplitN(value, "|", 3)
	if len(parts) < 2 {
		return nil
	}
	id := strings.TrimSpace(parts[0])
	if id == "" {
		return nil
	}
	desc := strings.TrimSpace(parts[1])
	var details []string
	if len(parts) == 3 && strings.TrimSpace(parts[2]) != "" {
		details = []string{strings.TrimSpace(parts[2])}
	}
	return &model.Finding{
		ID:          id,
		Category:    model.CategoryFromID(id),
		Description: desc,
		Severity:    severity,
		Details:     details,
		Source:      "lynis",
		Raw:         raw,
	}
}
```

- [ ] **Step 6: Implement `internal/scanner/lynis/runner.go`**

```go
package lynis

import (
	"context"
	"fmt"
	"os"

	"github.com/maestroi/hardener/internal/model"
	"github.com/maestroi/hardener/internal/scanner"
)

// LynisScanner implements scanner.Scanner using the lynis binary.
type LynisScanner struct {
	binaryPath string
	extraFlags []string
}

// New creates a LynisScanner.
func New(binaryPath string, extraFlags []string) *LynisScanner {
	return &LynisScanner{binaryPath: binaryPath, extraFlags: extraFlags}
}

// Run executes lynis audit system. (Full implementation in Milestone 2.)
func (s *LynisScanner) Run(_ context.Context, opts scanner.ScanOptions) error {
	return fmt.Errorf("lynis Run not implemented in Milestone 1")
}

// ParseReport reads and parses a lynis-report.dat file from disk.
func (s *LynisScanner) ParseReport(_ context.Context, path string) ([]*model.Finding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading report %s: %w", path, err)
	}
	return ParseReportBytes(data)
}

// Score reads the hardening_index from a lynis-report.dat file.
func (s *LynisScanner) Score(_ context.Context, path string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, fmt.Errorf("reading report %s: %w", path, err)
	}
	return ScoreFromBytes(data)
}
```

- [ ] **Step 7: Run parser tests**

```bash
go test ./internal/scanner/... -v
```

Expected: all PASS.

- [ ] **Step 8: Commit**

```bash
git add testdata/ internal/scanner/
git commit -m "feat: implement Lynis report parser with warning/suggestion/score extraction"
```

---

### Task 8: Implement Reporters

**Files:**
- Create: `internal/reporter/reporter.go`
- Create: `internal/reporter/json.go`
- Create: `internal/reporter/terminal.go`
- Create: `internal/reporter/json_test.go`
- Create: `internal/reporter/terminal_test.go`

- [ ] **Step 1: Create `internal/reporter/reporter.go`**

```go
package reporter

import (
	"context"

	"github.com/maestroi/hardener/internal/model"
)

// Reporter renders output to the operator. Implementations must not contain business logic.
type Reporter interface {
	Audit(ctx context.Context, findings []*model.Finding, score int) error
	Plan(ctx context.Context, actions []*model.PlannedAction) error
	Applied(ctx context.Context, run *model.Run, actions []*model.AppliedAction) error
	Score(ctx context.Context, before, after int, skipped []string) error
	RollbackPreview(ctx context.Context, manifest *model.RollbackManifest) error
	History(ctx context.Context, runs []*model.Run) error
}
```

- [ ] **Step 2: Write failing JSON reporter tests**

```go
// internal/reporter/json_test.go
package reporter_test

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/maestroi/hardener/internal/model"
	"github.com/maestroi/hardener/internal/reporter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJSONReporter_Audit(t *testing.T) {
	var buf bytes.Buffer
	r := reporter.NewJSONReporter(&buf)

	findings := []*model.Finding{
		{ID: "SSH-7408", Category: "SSH", Description: "PermitRootLogin not disabled", Severity: model.SeverityWarning, Source: "lynis"},
	}
	err := r.Audit(context.Background(), findings, 62)
	require.NoError(t, err)

	var out struct {
		Score    int              `json:"score"`
		Findings []*model.Finding `json:"findings"`
	}
	require.NoError(t, json.Unmarshal(buf.Bytes(), &out))
	assert.Equal(t, 62, out.Score)
	require.Len(t, out.Findings, 1)
	assert.Equal(t, "SSH-7408", out.Findings[0].ID)
}

func TestJSONReporter_Plan(t *testing.T) {
	var buf bytes.Buffer
	r := reporter.NewJSONReporter(&buf)

	actions := []*model.PlannedAction{
		{FindingID: "SSH-7408", ModuleID: "ssh-hardening", Applicable: true, Risk: model.RiskMedium},
		{FindingID: "KRNL-6000", ModuleID: "kernel-sysctl", Applicable: false, SkipReason: "validator profile"},
	}
	err := r.Plan(context.Background(), actions)
	require.NoError(t, err)

	var out struct {
		Actions []*model.PlannedAction `json:"actions"`
	}
	require.NoError(t, json.Unmarshal(buf.Bytes(), &out))
	require.Len(t, out.Actions, 2)
	assert.True(t, out.Actions[0].Applicable)
	assert.False(t, out.Actions[1].Applicable)
}

func TestJSONReporter_Score(t *testing.T) {
	var buf bytes.Buffer
	r := reporter.NewJSONReporter(&buf)
	require.NoError(t, r.Score(context.Background(), 62, 81, []string{"KRNL-6000"}))

	var out struct {
		Before  int      `json:"before"`
		After   int      `json:"after"`
		Delta   int      `json:"delta"`
		Skipped []string `json:"skipped"`
	}
	require.NoError(t, json.Unmarshal(buf.Bytes(), &out))
	assert.Equal(t, 62, out.Before)
	assert.Equal(t, 81, out.After)
	assert.Equal(t, 19, out.Delta)
}
```

- [ ] **Step 3: Implement `internal/reporter/json.go`**

```go
package reporter

import (
	"context"
	"encoding/json"
	"io"

	"github.com/maestroi/hardener/internal/model"
)

// JSONReporter serializes output as JSON. All methods write a single JSON object per call.
type JSONReporter struct {
	w io.Writer
}

// NewJSONReporter creates a JSONReporter writing to w.
func NewJSONReporter(w io.Writer) *JSONReporter {
	return &JSONReporter{w: w}
}

func (r *JSONReporter) encode(v interface{}) error {
	enc := json.NewEncoder(r.w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func (r *JSONReporter) Audit(_ context.Context, findings []*model.Finding, score int) error {
	return r.encode(map[string]interface{}{
		"score":    score,
		"findings": findings,
	})
}

func (r *JSONReporter) Plan(_ context.Context, actions []*model.PlannedAction) error {
	return r.encode(map[string]interface{}{"actions": actions})
}

func (r *JSONReporter) Applied(_ context.Context, run *model.Run, actions []*model.AppliedAction) error {
	return r.encode(map[string]interface{}{
		"run":     run,
		"actions": actions,
	})
}

func (r *JSONReporter) Score(_ context.Context, before, after int, skipped []string) error {
	return r.encode(map[string]interface{}{
		"before":  before,
		"after":   after,
		"delta":   after - before,
		"skipped": skipped,
	})
}

func (r *JSONReporter) RollbackPreview(_ context.Context, manifest *model.RollbackManifest) error {
	return r.encode(manifest)
}

func (r *JSONReporter) History(_ context.Context, runs []*model.Run) error {
	return r.encode(map[string]interface{}{"runs": runs})
}
```

- [ ] **Step 4: Run JSON reporter tests**

```bash
go test ./internal/reporter/... -run TestJSONReporter -v
```

Expected: all PASS.

- [ ] **Step 5: Write failing terminal reporter tests**

```go
// internal/reporter/terminal_test.go
package reporter_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/maestroi/hardener/internal/model"
	"github.com/maestroi/hardener/internal/reporter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTerminalReporter_Audit_ContainsFindings(t *testing.T) {
	var buf bytes.Buffer
	r := reporter.NewTerminalReporter(&buf)

	findings := []*model.Finding{
		{ID: "SSH-7408", Category: "SSH", Description: "PermitRootLogin not disabled", Severity: model.SeverityWarning},
		{ID: "KRNL-6000", Category: "KRNL", Description: "Sysctl values differ", Severity: model.SeverityInfo},
	}
	err := r.Audit(context.Background(), findings, 62)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "SSH-7408")
	assert.Contains(t, output, "KRNL-6000")
	assert.Contains(t, output, "62")
}

func TestTerminalReporter_Plan_ShowsApplicableAndSkipped(t *testing.T) {
	var buf bytes.Buffer
	r := reporter.NewTerminalReporter(&buf)

	actions := []*model.PlannedAction{
		{FindingID: "SSH-7408", ModuleID: "ssh-hardening", Title: "Harden SSH", Applicable: true, Risk: model.RiskMedium, CanRollback: true},
		{FindingID: "KRNL-6000", ModuleID: "kernel-sysctl", Title: "Tune sysctl", Applicable: false, SkipReason: "validator profile blocks kernel changes"},
	}
	err := r.Plan(context.Background(), actions)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "SSH-7408")
	assert.Contains(t, output, "KRNL-6000")
	assert.Contains(t, output, "validator profile blocks kernel changes")
}

func TestTerminalReporter_Score_ShowsDelta(t *testing.T) {
	var buf bytes.Buffer
	r := reporter.NewTerminalReporter(&buf)
	require.NoError(t, r.Score(context.Background(), 62, 81, nil))

	output := buf.String()
	assert.Contains(t, output, "62")
	assert.Contains(t, output, "81")
	assert.Contains(t, output, "+19")
}
```

- [ ] **Step 6: Implement `internal/reporter/terminal.go`**

```go
package reporter

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/fatih/color"
	"github.com/olekukonko/tablewriter"

	"github.com/maestroi/hardener/internal/model"
)

var (
	colorWarning  = color.New(color.FgYellow, color.Bold)
	colorCritical = color.New(color.FgRed, color.Bold)
	colorOK       = color.New(color.FgGreen)
	colorSkipped  = color.New(color.FgHiBlack)
	colorScore    = color.New(color.FgCyan, color.Bold)
)

// TerminalReporter renders human-readable colored output to a writer.
type TerminalReporter struct {
	w io.Writer
}

// NewTerminalReporter creates a TerminalReporter. Pass os.Stdout for production use.
func NewTerminalReporter(w io.Writer) *TerminalReporter {
	// Disable color when writing to a buffer (tests), enable for os.Stdout.
	if w != os.Stdout {
		color.NoColor = true
	}
	return &TerminalReporter{w: w}
}

func (r *TerminalReporter) Audit(_ context.Context, findings []*model.Finding, score int) error {
	fmt.Fprintf(r.w, "\nHardening score: %s\n\n", colorScore.Sprintf("%d", score))

	tbl := tablewriter.NewWriter(r.w)
	tbl.SetHeader([]string{"ID", "Category", "Severity", "Description"})
	tbl.SetBorder(false)
	tbl.SetColumnSeparator("  ")
	tbl.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
	tbl.SetAlignment(tablewriter.ALIGN_LEFT)
	tbl.SetAutoWrapText(true)
	tbl.SetColWidth(60)

	for _, f := range findings {
		sev := severityLabel(f.Severity)
		desc := truncate(f.Description, 60)
		tbl.Append([]string{f.ID, f.Category, sev, desc})
	}
	tbl.Render()
	fmt.Fprintf(r.w, "\n%d finding(s)\n", len(findings))
	return nil
}

func (r *TerminalReporter) Plan(_ context.Context, actions []*model.PlannedAction) error {
	applicable := make([]*model.PlannedAction, 0)
	skipped := make([]*model.PlannedAction, 0)
	for _, a := range actions {
		if a.Applicable {
			applicable = append(applicable, a)
		} else {
			skipped = append(skipped, a)
		}
	}

	fmt.Fprintf(r.w, "\nRemediation plan — %d applicable, %d skipped\n\n", len(applicable), len(skipped))

	if len(applicable) > 0 {
		tbl := tablewriter.NewWriter(r.w)
		tbl.SetHeader([]string{"Finding", "Module", "Risk", "Impact", "Rollback", "Reboot"})
		tbl.SetBorder(false)
		tbl.SetColumnSeparator("  ")
		tbl.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
		tbl.SetAlignment(tablewriter.ALIGN_LEFT)
		for _, a := range applicable {
			rb := "yes"
			if !a.CanRollback {
				rb = "no"
			}
			reboot := "-"
			if a.RequiresReboot {
				reboot = "YES"
			}
			tbl.Append([]string{a.FindingID, a.ModuleID, a.Risk.String(), truncate(a.Impact, 40), rb, reboot})
		}
		tbl.Render()
	}

	if len(skipped) > 0 {
		fmt.Fprintf(r.w, "\nSkipped:\n")
		for _, a := range skipped {
			fmt.Fprintf(r.w, "  %s  %s\n", colorSkipped.Sprint(a.FindingID), a.SkipReason)
		}
	}
	return nil
}

func (r *TerminalReporter) Applied(_ context.Context, run *model.Run, actions []*model.AppliedAction) error {
	fmt.Fprintf(r.w, "\nRun: %s  Status: %s\n\n", run.ID, string(run.Status))

	tbl := tablewriter.NewWriter(r.w)
	tbl.SetHeader([]string{"Finding", "Module", "Status", "Error"})
	tbl.SetBorder(false)
	tbl.SetColumnSeparator("  ")
	tbl.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
	tbl.SetAlignment(tablewriter.ALIGN_LEFT)
	for _, a := range actions {
		errMsg := truncate(a.Error, 40)
		tbl.Append([]string{a.FindingID, a.ModuleID, string(a.Status), errMsg})
	}
	tbl.Render()
	return nil
}

func (r *TerminalReporter) Score(_ context.Context, before, after int, skipped []string) error {
	delta := after - before
	sign := "+"
	if delta < 0 {
		sign = ""
	}
	fmt.Fprintf(r.w, "\nHardening score:  %d  →  %s  (%s%d)\n",
		before,
		colorScore.Sprintf("%d", after),
		sign, delta,
	)
	if len(skipped) > 0 {
		fmt.Fprintf(r.w, "Skipped findings: %s\n", strings.Join(skipped, ", "))
	}
	return nil
}

func (r *TerminalReporter) RollbackPreview(_ context.Context, manifest *model.RollbackManifest) error {
	fmt.Fprintf(r.w, "\nRollback preview for run %s — %d entries\n\n", manifest.RunID, len(manifest.Entries))
	for _, e := range manifest.Entries {
		fmt.Fprintf(r.w, "  [%d] %s  %s\n", e.Index, string(e.Kind), e.Description)
	}
	return nil
}

func (r *TerminalReporter) History(_ context.Context, runs []*model.Run) error {
	if len(runs) == 0 {
		fmt.Fprintln(r.w, "No runs found.")
		return nil
	}
	tbl := tablewriter.NewWriter(r.w)
	tbl.SetHeader([]string{"Run ID", "Started", "Status", "Profile", "Before", "After"})
	tbl.SetBorder(false)
	tbl.SetColumnSeparator("  ")
	tbl.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
	tbl.SetAlignment(tablewriter.ALIGN_LEFT)
	for _, run := range runs {
		tbl.Append([]string{
			run.ID,
			run.StartedAt.Format("2006-01-02 15:04"),
			string(run.Status),
			run.ProfileName,
			fmt.Sprintf("%d", run.ScoreBefore),
			fmt.Sprintf("%d", run.ScoreAfter),
		})
	}
	tbl.Render()
	return nil
}

func severityLabel(s model.Severity) string {
	switch s {
	case model.SeverityWarning:
		return colorWarning.Sprint("WARNING")
	case model.SeverityCritical:
		return colorCritical.Sprint("CRITICAL")
	default:
		return "INFO"
	}
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-1] + "…"
}
```

- [ ] **Step 7: Run all reporter tests**

```bash
go test ./internal/reporter/... -v
```

Expected: all PASS.

- [ ] **Step 8: Run full test suite**

```bash
go test ./... -v 2>&1 | tail -20
```

Expected: all packages PASS.

- [ ] **Step 9: Build the final binary**

```bash
go build -o hardener .
./hardener --help
./hardener audit
./hardener plan
```

Expected: commands print "not yet implemented", no panics.

- [ ] **Step 10: Commit**

```bash
git add internal/reporter/
git commit -m "feat: implement JSON and terminal reporters"
```

- [ ] **Step 11: Final Milestone 1 commit with all files**

```bash
git add .
git status
git commit -m "chore: milestone 1 complete — foundation, interfaces, parser, reporters"
```
