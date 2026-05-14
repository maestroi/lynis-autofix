# Design: audit and report commands

**Date:** 2026-05-14  
**Status:** Approved  

## Problem

`cmd/audit.go` and `cmd/report.go` are stubs that print "not yet implemented." The `Reporter` interface, `StateManager`, and `LynisScanner.ParseReport()` are all fully implemented — the commands just need to be wired up. `LynisScanner.Run()` is also a stub and must be implemented to support subprocess invocation of Lynis.

## Delivery

Two sequential plans:

1. **Plan 1 — `audit` command:** Implement `LynisScanner.Run()`, add scan persistence to state, wire `cmd/audit.go`
2. **Plan 2 — `report` command:** Wire `cmd/report.go` history mode, implement compliance drill-down with live Lynis re-scan

Plan 2 executes after Plan 1 ships so real run history exists to test the compliance comparison against.

---

## Plan 1: `audit` command

### Behaviour

```
hardener audit                        # run Lynis, display findings + score
hardener audit --fresh                # force new Lynis scan even if cached
hardener audit --report-path <file>   # parse existing .dat, skip subprocess
hardener audit --format json          # JSON output
```

**Flow:**
1. If `--report-path` given → skip subprocess, parse that file
2. Otherwise, try `lynis audit system` as subprocess
3. If Lynis binary not found → fall back to latest cached scan in state; if no cache exists, exit with a clear error
4. Parse via `LynisScanner.ParseReport()` (already implemented)
5. Display via `TerminalReporter.Audit()` or `JSONReporter.Audit()`
6. Persist scan result to `<stateDir>/scans/<timestamp>-scan.json`

### `LynisScanner.Run()` implementation

Calls `exec.Command("lynis", "audit", "system", "--report-file", path, "--no-colors", "--quiet")` with a 5-minute default timeout. Streams stdout/stderr to a log file under state dir. Returns an error if the exit code is non-zero, including trimmed stderr in the message.

### Scan persistence

New `ScanResult` model:

```go
type ScanResult struct {
    Timestamp  time.Time       `json:"timestamp"`
    ReportPath string          `json:"report_path"`
    Score      int             `json:"score"`
    Findings   []*Finding      `json:"findings"`
}
```

Stored at `<stateDir>/scans/<unix-nano>-scan.json`. Three new `StateManager` methods:
- `SaveScan(ctx, result) error`
- `LatestScan(ctx) (*ScanResult, error)` — returns most recent, or `ErrNoScans`
- `ListScans(ctx) ([]*ScanResult, error)`

### Error handling

| Condition | Behaviour |
|---|---|
| Lynis binary not found | Fall back to latest cached scan with `[warn]` notice; error if no cache |
| Lynis exits non-zero | Return error with trimmed stderr |
| `--report-path` file missing | Return error immediately |
| Parse error in `.dat` file | Return error with file path |

---

## Plan 2: `report` command

### Behaviour

```
hardener report                       # history table of all apply runs
hardener report --run-id <id>         # compliance drill-down for one run
hardener report --format json         # JSON output (either mode)
```

**History mode (`hardener report`):**  
Calls `StateManager.ListRuns()` → `TerminalReporter.History()`. Purely wiring — no new logic.

**Drill-down mode (`hardener report --run-id <id>`):**
1. Load stored run (plan + applied actions) from `FileStore`
2. Re-run Lynis (same subprocess logic as `audit`; temp file, cleaned up after)
3. Compare current findings against stored plan:
   - **Fixed** — `Applicable: true` in stored plan, absent from current scan
   - **Still open** — `Applicable: true` in stored plan, present in current scan
   - **Skipped** — `Applicable: false` in stored plan
   - **New** — present in current scan, not in stored plan at all
4. Display compliance summary: score at run time → current score, finding breakdown by status
5. If Lynis unavailable during drill-down → show stored plan/applied data with `[warn] live comparison unavailable: <reason>`

`report` is **read-only** — no state is written. The Lynis re-scan uses a temp file cleaned up after comparison.

### Error handling

| Condition | Behaviour |
|---|---|
| Run ID not found | Clear error: "run <id> not found" |
| Lynis unavailable during drill-down | Degrade gracefully: show stored data + warn |
| No runs in history | Print "No runs found." (already in `TerminalReporter.History`) |

---

## Architecture

**No new abstractions.** All new logic lives in the command files or existing packages.

### Files changed

| File | Change |
|---|---|
| `internal/model/scan.go` | Create — `ScanResult` struct |
| `internal/scanner/lynis/runner.go` | Implement `Run()` |
| `internal/state/manager.go` | Add `SaveScan`, `LatestScan`, `ListScans` to interface |
| `internal/state/store.go` | Implement the three new scan methods |
| `cmd/audit.go` | Implement — wire scanner → reporter → state |
| `cmd/report.go` | Implement — history mode + compliance drill-down |

### Testing

| Component | Approach |
|---|---|
| `LynisScanner.Run()` | Inject a shell script that writes a fixture `.dat` and exits 0; assert report path created |
| `audit` command | Integration test via `--report-path` with a fixture `.dat`; no subprocess |
| Compliance comparison logic | Unit test with fixture stored plan + fixture findings; no subprocess |
| `report` history mode | Unit test with in-memory/file state stub |
| Scan persistence | Unit test `SaveScan` / `LatestScan` round-trip |
