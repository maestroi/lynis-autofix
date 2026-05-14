# Hardener — Design Specification

**Date:** 2026-05-13
**Status:** Approved
**Author:** maestroi

---

## 1. Purpose

`hardener` is a production-grade Linux hardening automation tool that acts as a remediation engine for Lynis audit findings. It is **not** a replacement for Lynis — it consumes Lynis output and applies safe, idempotent, rollback-capable fixes to Ubuntu servers, VPS instances, Docker hosts, and blockchain validator/RPC nodes.

### Core philosophy

- **Explainable** — every action is shown before it runs
- **Safe-by-default** — safety gates block dangerous actions; profiles restrict scope
- **Idempotent** — running twice produces the same result as running once
- **Modular** — each fix is a self-contained Go module
- **Rollback-capable** — every mutation is reversible from a manifest
- **Profile-based** — infrastructure-aware policy drives what is allowed
- **Infrastructure-friendly** — never blindly breaks networking, validators, Docker, or SSH

### What it must never do

- Lock out SSH access
- Block P2P or consensus traffic
- Interfere with Docker bridge networking or iptables
- Touch protected ports, processes, or services declared in the active profile
- Apply a firewall rule that drops the current SSH session
- Restart sshd with an invalid configuration

---

## 2. Target Environments

- Ubuntu Server 22.04 / 24.04 (MVP)
- Baremetal and VPS
- Docker hosts
- Blockchain validator and RPC nodes (chain-agnostic via profile YAML)

Future: multi-distro support, remote fleet mode, API server.

---

## 3. CLI Structure

```
hardener [global flags] <command>

Commands:
  audit      Run Lynis and display findings + current hardening score
  plan       Show remediation plan without applying anything
  apply      Apply the remediation plan
  rollback   Reverse a previous run
  report     Show run history and before/after scores

Global flags:
  --state-dir string    Override state directory (default: /var/lib/hardener)
  --profile   string    Profile name or path to .yaml file (default: server)
  --output    string    Output format: table|json (default: table)
  --config    string    Path to hardener.yaml config file
  --verbose             Include debug-level detail
```

### Command flags

```
hardener audit
  --fresh               Force a new Lynis scan (ignore cached report)
  --report-path string  Parse a specific report file

hardener plan
  --fresh               Run Lynis scan before planning
  --finding strings     Limit to specific finding IDs (e.g. SSH-7408,KRNL-6000)
  --module  strings     Limit to specific module IDs

hardener apply
  --audit               Run fresh Lynis scan before applying
  --dry-run             No mutations; uses DryRunExecutor
  --yes                 Skip confirmation prompt
  --confirm-dangerous   Allow Dangerous=true actions
  --finding strings     Apply only specific findings
  --module  strings     Apply only specific modules

hardener rollback
  --run-id string       Run ID to roll back (required unless --list)
  --dry-run             Preview rollback without executing
  --yes                 Skip confirmation prompt
  --list                List runs that have rollback manifests

hardener report
  --run-id string       Drill into a single run (all runs if omitted)
```

**Rules:**
- `--dry-run` exists only on `apply` and `rollback`. Other commands are already read-only.
- `audit` is stateless — it never creates a run directory or writes to state.
- The `cmd/` layer contains zero business logic; it parses flags and wires components.

---

## 4. Package Structure

```
hardener/
├── main.go
├── cmd/                            # Cobra CLI entry points — wiring only
│   ├── root.go
│   ├── audit.go
│   ├── plan.go
│   ├── apply.go
│   ├── rollback.go
│   └── report.go
│
├── internal/
│   ├── model/                      # Pure data types — no I/O, no imports from sibling packages
│   │   ├── finding.go
│   │   ├── action.go
│   │   ├── profile.go
│   │   ├── rollback.go
│   │   ├── run.go
│   │   └── report.go
│   │
│   ├── modules/                    # Remediation modules + Module interface
│   │   ├── module.go               # Module interface, ModuleMetadata
│   │   ├── ssh/
│   │   ├── auth/
│   │   ├── kernel/
│   │   ├── packages/
│   │   ├── firewall/
│   │   ├── files/
│   │   ├── services/
│   │   ├── boot/
│   │   └── logging/
│   │
│   ├── registry/
│   │   ├── registry.go             # Registry type — maps finding IDs and module IDs to modules
│   │   └── init.go                 # Only file that imports concrete module packages
│   │
│   ├── executor/
│   │   ├── executor.go             # Executor interface (embeds Inspector)
│   │   ├── inspector.go            # Inspector interface (read-only subset)
│   │   ├── local.go                # LocalExecutor
│   │   └── dry.go                  # DryRunExecutor
│   │
│   ├── scanner/
│   │   ├── scanner.go              # Scanner interface
│   │   ├── lynis/
│   │   │   ├── runner.go
│   │   │   └── parser.go
│   │   └── mock/
│   │
│   ├── planner/
│   │   └── planner.go              # Maps findings → PlannedActions via registry
│   │
│   ├── safety/
│   │   ├── checker.go              # SafetyChecker interface + pipeline
│   │   ├── ssh.go                  # Preflight: validate sshd config syntax
│   │   ├── firewall.go             # Preflight: never drop active SSH session
│   │   └── profile_filter.go       # Scope-aware protected resource enforcement
│   │
│   ├── backup/
│   │   └── store.go                # Snapshots files/sysctl/service state before mutation
│   │
│   ├── state/
│   │   ├── manager.go              # StateManager interface
│   │   └── store.go                # FileStore — manages run directories
│   │
│   ├── rollback/
│   │   └── manager.go              # Reads manifest, reverses entries in order
│   │
│   ├── reporter/
│   │   ├── reporter.go             # Reporter interface
│   │   ├── terminal.go             # Colored table output
│   │   └── json.go                 # JSON serialization
│   │
│   ├── config/
│   │   ├── loader.go               # Loads and merges config layers
│   │   ├── defaults.go             # Bundled defaults
│   │   ├── merge.go                # Layer merging (system → user → file → flags)
│   │   └── validate.go             # Fail-fast validation before any command runs
│   │
│   └── platform/
│       ├── detect.go               # Detects OS, version, init system
│       ├── ubuntu.go               # Ubuntu-specific helpers
│       └── systemd.go              # Systemd service name resolution
│
├── internal/embed/
│   └── profiles/
│       ├── minimal.yaml
│       ├── server.yaml             # Default profile
│       ├── docker-host.yaml
│       └── validator-node.example.yaml  # Template; embedded but not applied by default
│
└── testdata/
    ├── lynis-reports/              # Sample Lynis report files for parser tests
    └── profiles/                   # Profile fixtures for config tests
```

### Architectural boundary rules

- `internal/model/` imports nothing from other internal packages — it is the foundation
- All pipeline components depend on interfaces and `model` types only, never on each other's concrete types
- `internal/registry/init.go` is the **only** file that imports concrete module packages
- `cmd/` has no business logic — only flag parsing and component wiring
- Modules use `Executor`/`Inspector` semantic methods; they never construct raw shell commands directly
- YAML is used for profiles and config only; remediation logic lives in Go

---

## 5. Core Interfaces

### Inspector — read-only system access

```go
type Inspector interface {
    ReadFile(ctx context.Context, path string) ([]byte, error)
    FileExists(ctx context.Context, path string) (bool, error)
    GetSysctl(ctx context.Context, key string) (string, error)
    ServiceState(ctx context.Context, name string) (ServiceStatus, error)
    IsPackageInstalled(ctx context.Context, name string) (bool, error)
    RunReadOnly(ctx context.Context, name string, args ...string) (CmdOutput, error)
}
```

### Executor — semantic mutations, embeds Inspector

```go
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

    // Escape hatch — for cases with no semantic method (e.g., sshd -t)
    Run(ctx context.Context, name string, args ...string) (CmdOutput, error)

    IsDryRun() bool
}
```

`LocalExecutor` performs real syscalls. `DryRunExecutor` logs every call and returns safe synthetic results — zero side effects. The pipeline never knows which it holds.

### Module interface

```go
// Lives in internal/modules/module.go

type Module interface {
    Metadata() ModuleMetadata
    SupportedFindings() []string

    // Read-only inspection allowed. No mutations.
    Plan(ctx context.Context, finding *model.Finding,
         profile *model.Profile, inspect executor.Inspector) (*model.PlannedAction, error)

    // Receives PlannedAction. Module is stateless — no shared state from Plan().
    Apply(ctx context.Context, action *model.PlannedAction,
          exec executor.Executor) (*model.AppliedAction, error)

    // Read-only confirmation that desired end state is present.
    Validate(ctx context.Context, action *model.PlannedAction,
             inspect executor.Inspector) error

    // Reverses a single RollbackEntry. Called by rollback engine, not by module itself.
    Rollback(ctx context.Context, entry *model.RollbackEntry,
             exec executor.Executor) error
}

type ModuleMetadata struct {
    ID               string
    Name             string
    Description      string
    Category         string
    DefaultRisk      model.RiskLevel
    SupportedDistros []string
    Tags             []string        // "network-safe", "docker-safe", "validator-safe"
    CanRollback      bool
    RequiresReboot   bool
}
```

**Module contract:**
- `Plan()` and `Validate()` receive only `Inspector` — compiler enforces no-mutation
- `Apply()` and `Rollback()` receive `Executor` — mutations allowed
- Modules are stateless structs — no shared state between method calls
- `Plan()` is finding-specific: modules supporting multiple finding IDs plan only what is relevant to the finding passed in
- Modules never create backups — `backup.Store` owns all snapshot creation before mutation
- Modules never construct raw shell strings; they use Executor semantic methods

### Scanner interface

```go
type Scanner interface {
    Run(ctx context.Context, opts ScanOptions) error
    ParseReport(ctx context.Context, path string) ([]*model.Finding, error)
    Score(ctx context.Context, path string) (int, error)
}
```

### SafetyChecker interface

```go
type SafetyChecker interface {
    Check(ctx context.Context, action *model.PlannedAction,
          exec executor.Executor) (*SafetyResult, error)
}

type SafetyResult struct {
    Safe    bool
    Reason  string   // populated when Safe == false; shown in plan output
    Warning string   // shown even when Safe == true (advisory)
}
```

### Reporter interface

```go
type Reporter interface {
    Audit(ctx context.Context, findings []*model.Finding, score int) error
    Plan(ctx context.Context, actions []*model.PlannedAction) error
    Applied(ctx context.Context, run *model.Run) error
    Score(ctx context.Context, before, after int, skipped []string) error
    Rollback(ctx context.Context, manifest *model.RollbackManifest) error
    History(ctx context.Context, runs []*model.Run) error
}
```

`TerminalReporter` renders colored tables. `JSONReporter` serializes the same model types. Both consume identical inputs — no logic in reporters, only presentation.

---

## 6. Data Models

### Findings

```go
type Finding struct {
    ID          string    // "SSH-7408"
    Category    string    // "SSH", "Kernel", "Auth"
    Description string
    Severity    Severity
    Details     []string
    Source      string    // "lynis" | "openscap" | "custom"
    Raw         string    // original line preserved for debugging
}

type Severity int
const (
    SeverityInfo     Severity = iota  // lynis suggestion
    SeverityWarning                   // lynis warning
    SeverityCritical                  // reserved for future scanners
)
```

### Actions

```go
type PlannedAction struct {
    FindingID      string
    ModuleID       string
    Title          string
    Description    string
    Steps          []string             // human-readable; shown in `hardener plan`
    Metadata       map[string]string    // machine-readable: target_file, sysctl_key, etc.
    Risk           RiskLevel
    Impact         string               // one-line: "Restarts sshd"
    RequiresReboot bool
    CanRollback    bool
    Dangerous      bool
    Applicable     bool
    SkipReason     string               // populated when Applicable == false
    Tags           []string
}

type AppliedAction struct {
    PlannedAction                       // embedded — plan preserved alongside outcome
    AppliedAt     time.Time
    Status        ActionStatus
    Error         string                // non-empty when Status == ActionFailed
    RollbackKeys  []string             // references into RollbackManifest entries
}

type ActionStatus string
const (
    ActionPlanned      ActionStatus = "planned"
    ActionSkipped      ActionStatus = "skipped"
    ActionApplied      ActionStatus = "applied"
    ActionFailed       ActionStatus = "failed"
    ActionRolledBack   ActionStatus = "rolled_back"
    ActionNotAttempted ActionStatus = "not_attempted"
)

type RiskLevel int
const (
    RiskNone     RiskLevel = iota
    RiskLow                        // config tweak, no service restart
    RiskMedium                     // service restart, sysctl change
    RiskHigh                       // firewall rule, kernel param
    RiskCritical                   // requires --confirm-dangerous
)
```

All five `ActionStatus` values are written to `applied.json` for every planned action regardless of outcome. `hardener report` always has a complete picture.

### Rollback

```go
type RollbackManifest struct {
    RunID     string
    CreatedAt time.Time
    Entries   []RollbackEntry
    Complete  bool   // false if apply was interrupted mid-run
}

type RollbackEntry struct {
    Index       int           // application order; rollback reverses descending
    CreatedAt   time.Time
    Description string        // e.g. "Restore /etc/ssh/sshd_config before SSH-7408"
    ModuleID    string
    FindingID   string
    Kind        RollbackKind

    // File
    Path        string
    BackupPath  string        // absolute, under /var/lib/hardener/backups/<run-id>/
    OrigMode    fs.FileMode
    OrigUID     int
    OrigGID     int

    // Sysctl
    SysctlKey   string
    SysctlValue string        // value before change

    // Service
    ServiceName string
    WasEnabled  bool
    WasActive   bool

    // Package
    PackageName  string
    WasInstalled bool         // false = absent before hardener installed it
}

type RollbackKind string
const (
    RollbackFile    RollbackKind = "file"
    RollbackSysctl  RollbackKind = "sysctl"
    RollbackService RollbackKind = "service"
    RollbackPackage RollbackKind = "package"
)
```

**Package rollback rule:** only remove a package if `WasInstalled == false`. Never autoremove dependencies. Package removal is skipped in safe profiles — the default behavior is to leave installed packages in place even on rollback.

**Rollback ordering:** `Index` is recorded in application order. The rollback engine sorts entries by `Index` descending and reverses them. Within a module, `backup.Store` records the rollback entry *before* any mutation — if the process is killed mid-apply, the manifest is always current enough to recover.

### Profile

```go
type Profile struct {
    Name        string
    Description string

    AllowedModules  []string    // empty = all allowed
    BlockedModules  []string

    // Scope-aware: protected_ports only blocks firewall/network/sysctl modules.
    // SSH config hardening on port 22 is unaffected by protected_ports: [22].
    ProtectedPorts      []int
    ProtectedPortRanges []PortRange
    ProtectedProcesses  []string  // blocks process-kill/restart modules only
    ProtectedServices   []string  // blocks service-disable/restart modules only

    MaxRiskLevel   RiskLevel
    RequireConfirm []string    // module IDs needing explicit confirmation

    SysctlPolicy SysctlPolicy
    FailurePolicy FailurePolicy
}

type PortRange struct {
    Start int
    End   int
    Proto string  // "tcp" | "udp" | "both"
}

type SysctlPolicy struct {
    AllowNetworkChanges bool
    AllowKernelChanges  bool
    BlockedKeys         []string
}

type FailurePolicy string
const (
    FailureRollbackAndStop     FailurePolicy = "rollback_failed_and_stop"      // default
    FailureRollbackAndContinue FailurePolicy = "rollback_failed_and_continue"  // CI use
    FailureRollbackEntireRun   FailurePolicy = "rollback_entire_run"           // paranoid
    FailureStopWithoutRollback FailurePolicy = "stop_without_rollback"
)
```

### Run

```go
type Run struct {
    ID           string
    StartedAt    time.Time
    FinishedAt   *time.Time
    ProfileName  string
    ScannerSource string      // "lynis" | "openscap" | "custom"
    StateDir     string
    DryRun       bool
    Status       RunStatus
    ScoreBefore  int
    ScoreAfter   int

    // System context — populated by platform.Detect() at run start
    OSName        string
    OSVersion     string
    KernelVersion string
    Hostname      string
}

type RunStatus string
const (
    RunPlanning   RunStatus = "planning"
    RunApplying   RunStatus = "applying"
    RunCompleted  RunStatus = "completed"
    RunFailed     RunStatus = "failed"
    RunRolledBack RunStatus = "rolled_back"
)
```

`Run` is a thin index record. Full detail lives in `plan.json`, `applied.json`, and `rollback.json` in the run directory. `history.jsonl` contains one `Run` JSON object per line.

---

## 7. State Directory Layout

```
/var/lib/hardener/                  (or --state-dir override)
  runs/
    <run-id>/
      plan.json                     all PlannedActions for this run
      applied.json                  all AppliedActions (every status, not just success)
      rollback.json                 RollbackManifest
      logs/
        apply.log
  backups/
    <run-id>/
      <sha256-of-original-path>/
        file                        raw backup bytes
        meta.json                   mode, uid, gid, original path
  history.jsonl                     one Run JSON per line
  locks/
    apply.lock                      prevents concurrent apply runs
```

All state is centralized. Hardener never scatters backup files around the system. The entire state for a run can be inspected, archived, or deleted as a single directory.

---

## 8. Execution Pipeline

### `hardener audit` (stateless)

```
1. platform.Detect() → OSInfo
2. LynisScanner.Run() if --fresh, otherwise use existing report
3. LynisScanner.ParseReport() → []Finding
4. LynisScanner.Score() → int
5. Reporter.Audit(findings, score)
```

No run directory created. No state written.

### `hardener plan` (stateless)

```
1. platform.Detect()
2. Parse report (--fresh triggers new scan)
3. For each Finding:
   a. registry.Lookup(finding.ID)           → skip with warning if not found
   b. Module.Plan(ctx, finding, profile, inspector) → PlannedAction
   c. SafetyCheckers.Check(action)           → mark Applicable=false + SkipReason if blocked
   d. Profile filter: blocked modules, MaxRiskLevel, protected resources (scope-aware)
4. Reporter.Plan(actions)
```

No run directory created. No state written. Inspector uses real read-only OS access.

### `hardener apply`

```
 1. platform.Detect()
 2. Acquire locks/apply.lock (fail if another apply is running)
 3. Parse report (--audit triggers fresh scan)
 4. Plan phase (same as hardener plan above)
 5. Reporter.Plan(actions) → prompt confirmation unless --yes
 6. StateManager.InitRun() → creates runs/<run-id>/, writes Run to history.jsonl
 7. For each applicable PlannedAction (registration order):
    a. backup.Store.Snapshot(action)
         → copies affected files to backups/<run-id>/
         → captures current sysctl/service state
         → writes RollbackEntry to runs/<run-id>/rollback.json  ← BEFORE mutation
    b. Module.Apply(ctx, action, executor) → AppliedAction
    c. Module.Validate(ctx, action, inspector)
    d. On validation failure:
         per profile.FailurePolicy:
           rollback_failed_and_stop     → rollback this module, mark run Failed, stop
           rollback_failed_and_continue → rollback this module, continue next action
           rollback_entire_run          → rollback all applied entries, mark run RolledBack
           stop_without_rollback        → mark run Failed, stop, no rollback
    e. StateManager.RecordApplied(action)   ← writes to applied.json
    f. Remaining actions after stop: status = not_attempted, written to applied.json
 8. StateManager.CompleteRun(status)
 9. If --audit: LynisScanner.Run() + Score() for after-score
10. Reporter.Applied(run) + Reporter.Score(before, after, skipped)
11. Release apply.lock
```

**Key invariant:** `backup.Store.Snapshot()` and the rollback entry write always complete before any mutation. A crash between snapshot and mutation leaves the system unchanged and the manifest recoverable.

### `hardener rollback`

```
1. StateManager.LoadRollbackManifest(runID)
2. Reporter.Rollback(manifest) preview
3. Prompt confirmation unless --yes (--dry-run stops here)
4. Sort entries by Index descending (reverse application order)
5. For each RollbackEntry:
   a. registry.LookupByModuleID(entry.ModuleID) → Module
   b. Module.Rollback(ctx, entry, executor)
   c. StateManager.MarkEntryRolledBack(runID, entry.Index)
6. StateManager.CompleteRun(runID, RunRolledBack)
7. Reporter.Rollback(manifest)
```

Rollback is idempotent — checks current state matches backup before overwriting.

### `hardener report`

```
1. StateManager.ListRuns()         (or single run if --run-id given)
2. Load plan.json + applied.json + rollback.json per run
3. Reporter.History(runs)          summary table
4. Reporter.Score(before, after)   per-run delta
```

---

## 9. Safety Model

Safety checks are a mandatory pipeline stage between planning and execution. They are not optional and cannot be bypassed by profiles (only risk thresholds and module allow/block lists are profile-controlled).

### Safety checker pipeline

```
SSHChecker        Runs sshd -t against the proposed config. Blocks if invalid.
FirewallChecker   Enumerates active connections. Blocks any rule that would DROP
                  the source port/address of the current SSH session.
ProfileFilter     Scope-aware enforcement of Profile.Protected* fields:
                  - protected_ports    → blocks firewall/network/sysctl modules only
                  - protected_services → blocks service-disable/restart modules only
                  - protected_processes → blocks process-kill/restart modules only
                  SSH config hardening is unaffected by protected_ports: [22].
RiskFilter        Skips actions where action.Risk > profile.MaxRiskLevel.
DangerousFilter   Blocks Dangerous=true actions unless --confirm-dangerous is set.
```

Each checker returns `SafetyResult{Safe, Reason, Warning}`. Any `Safe: false` marks the action `Applicable: false` with the reason shown in plan output. All checkers run for every action — multiple reasons can accumulate.

### Mutation guards (inside Apply)

Distinct from preflight safety checks, mutation guards run after a file is written but before a service is restarted. The canonical example is `sshd -t` after writing `sshd_config`. If the guard fails, `Apply()` returns an error and the failure policy handles it. These are not `SafetyChecker` implementations — they are module-internal defensive assertions.

---

## 10. Profile YAML Schema

```yaml
name: server
description: "General-purpose hardening baseline for Ubuntu 22.04/24.04"

allowed_modules: []       # empty = all modules allowed
blocked_modules: []

protected_ports: []
protected_port_ranges: [] # [{start: 9000, end: 9001, proto: tcp}]
protected_processes: []
protected_services: []

# none | low | medium | high | critical
max_risk_level: high

require_confirm: []

sysctl_policy:
  allow_network_changes: true
  allow_kernel_changes: true
  blocked_keys: []

# rollback_failed_and_stop | rollback_failed_and_continue
# rollback_entire_run      | stop_without_rollback
failure_policy: rollback_failed_and_stop
```

### Profile overlays (user config)

Users add local overrides without copying the full bundled profile:

```yaml
# /etc/hardener/hardener.yaml
profile: docker-host
profile_overrides:
  protected_ports:
    - 8080
    - 9000
  blocked_modules:
    - auditd-basic
```

Overlays are additive and deduplicated for list fields (appended to the bundled profile's lists), replacing for scalar fields. A full profile copy is only needed when overriding `failure_policy`, `max_risk_level`, or `sysctl_policy`.

### Bundled profiles

| Profile | Description |
|---|---|
| `server` | General baseline (default) |
| `minimal` | Only critical/safe fixes |
| `docker-host` | Preserves Docker networking and iptables |
| `validator-node.example` | Template — embedded but not applied by default |

---

## 11. User Config Schema

```yaml
# /etc/hardener/hardener.yaml

version: "1"

profile: server
state_dir: /var/lib/hardener

lynis:
  binary: /usr/sbin/lynis
  report_path: /var/log/lynis-report.dat
  log_path: /var/log/lynis.log
  extra_flags: []

output: table
confirm_dangerous: false

# Additive overrides applied on top of the active profile
profile_overrides:
  protected_ports: []
  blocked_modules: []
```

### Config loading order

```
1. Bundled defaults            (internal/config/defaults.go)
2. /etc/hardener/hardener.yaml (system-wide)
3. ~/.config/hardener/hardener.yaml (user-level, skipped when running as root)
4. --config flag path
5. CLI flags                   (highest priority — always win)
```

`internal/config/validate.go` checks the merged config before any command runs. Unknown profile names, inaccessible state directories, and conflicting flags all produce a clear error before Lynis is ever invoked.

---

## 12. Example Module Contract (SSH Hardening)

Demonstrates the full module contract: stateless, finding-specific, Inspector-gated Plan, mutation-guarded Apply, read-only Validate, manifest-driven Rollback.

```
Module ID:    ssh-hardening
Finding IDs:  SSH-7408, SSH-7902
Risk:         Medium
Tags:         network-safe
Rollback:     yes
Reboot:       no
```

**Plan (SSH-7408):** reads `/etc/ssh/sshd_config` via Inspector. Detects which required directives are absent or misconfigured. Returns `Applicable: false` with skip reason if config already meets requirements. Returns human-readable `Steps` and machine-readable `Metadata` (target_file, change_count) otherwise.

**Apply:** reads current config, applies directive changes, writes with preserved mode/owner (file permission hardening is `FILE-6310`'s job). Runs `sshd -t` as mutation guard. If guard fails, returns error — failure policy applies (rollback + stop by default). If guard passes, restarts `platform.ServiceName("ssh")`.

**Validate:** re-reads config via Inspector, checks all required directives are present, verifies service is active.

**Rollback:** reads backup file from `entry.BackupPath`. Restores with original `OrigMode`, `OrigUID`, `OrigGID`. Runs `sshd -t` before restart — never restarts sshd with an invalid config even during rollback.

---

## 13. Testing Strategy

- **Unit tests:** all model types, config loading/merging, profile filter logic, parser
- **Module tests:** each module's Plan/Validate logic against fixture configs; Apply/Rollback against a mock executor
- **Idempotency tests:** apply a module twice; assert second run returns `Applicable: false`
- **Rollback tests:** apply a module, rollback, assert original state restored
- **DryRunExecutor tests:** full apply pipeline with DryRunExecutor; assert zero syscalls, zero file writes
- **Parser tests:** Lynis report fixtures in `testdata/lynis-reports/`; assert correct Finding extraction
- **Integration tests (Ubuntu):** full apply + rollback cycle against a real Ubuntu 22.04 environment

---

## 14. Future Roadmap

| Milestone | Scope |
|---|---|
| MVP | Local binary, Lynis integration, 8–10 modules, apply/rollback/report, server + docker-host profiles |
| v0.2 | OpenSCAP scanner backend, `platform.Detect()` multi-distro, additional modules |
| v0.3 | SSH fleet mode via `SSHExecutor`, multi-host `hardener apply --hosts` |
| v0.4 | Agent mode — lightweight daemon on target, API server on control node |
| v0.5 | Prometheus metrics, `hardener profiles init`, ChainTruth integration |
| v1.0 | Ansible integration, CI/CD artifact output, audit trail signing |
