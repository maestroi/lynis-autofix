# audit command Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement `hardener audit` — runs Lynis (or parses an existing report), displays findings + score, and persists the scan result to state for later comparison by `report --run-id`.

**Architecture:** `LynisScanner.Run()` invokes the lynis binary as a subprocess with a 5-min timeout. `cmd/audit.go` orchestrates: subprocess → fallback to cached scan → parse → display → persist. Scan results live in `<stateDir>/scans/`. Three new `StateManager` methods handle scan persistence.

**Tech Stack:** Go 1.22, `github.com/maestroi/hardener`, `os/exec`, testify.

---

## File Map

| File | Action | Purpose |
|------|--------|---------|
| `internal/model/scan.go` | Create | `ScanResult` struct |
| `internal/state/manager.go` | Modify | Add `SaveScan`, `LatestScan`, `ListScans` to interface |
| `internal/state/store.go` | Modify | Implement the three new scan methods; create `scans/` subdir |
| `internal/scanner/lynis/runner.go` | Modify | Implement `Run()` with subprocess + timeout; define `ErrLynisNotFound` |
| `cmd/audit.go` | Modify | Full implementation: subprocess → fallback → parse → display → persist |

---

## Task 1: ScanResult model and scan persistence

**Files:**
- Create: `internal/model/scan.go`
- Modify: `internal/state/manager.go`
- Modify: `internal/state/store.go`

- [ ] **Step 1.1: Write failing tests for scan persistence**

Create `internal/state/store_scan_test.go`:

```go
package state_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/maestroi/hardener/internal/model"
	"github.com/maestroi/hardener/internal/state"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSaveScanAndLatestScan(t *testing.T) {
	dir := t.TempDir()
	store, err := state.NewFileStore(dir)
	require.NoError(t, err)

	ctx := context.Background()
	result := &model.ScanResult{
		Timestamp:  time.Now().UTC(),
		ReportPath: "/var/log/lynis-report.dat",
		Score:      42,
		Findings: []*model.Finding{
			{ID: "SSH-7408", Category: "SSH", Severity: model.SeverityWarning, Description: "test finding"},
		},
	}

	err = store.SaveScan(ctx, result)
	require.NoError(t, err)

	latest, err := store.LatestScan(ctx)
	require.NoError(t, err)
	assert.Equal(t, result.Score, latest.Score)
	assert.Equal(t, result.ReportPath, latest.ReportPath)
	assert.Len(t, latest.Findings, 1)
	assert.Equal(t, "SSH-7408", latest.Findings[0].ID)
}

func TestLatestScan_NoScans(t *testing.T) {
	dir := t.TempDir()
	store, err := state.NewFileStore(dir)
	require.NoError(t, err)

	_, err = store.LatestScan(context.Background())
	assert.ErrorIs(t, err, state.ErrNoScans)
}

func TestListScans(t *testing.T) {
	dir := t.TempDir()
	store, err := state.NewFileStore(dir)
	require.NoError(t, err)

	ctx := context.Background()
	for i := 0; i < 3; i++ {
		err = store.SaveScan(ctx, &model.ScanResult{
			Timestamp: time.Now().UTC(),
			Score:     i * 10,
		})
		require.NoError(t, err)
	}

	scans, err := store.ListScans(ctx)
	require.NoError(t, err)
	assert.Len(t, scans, 3)
}
```

- [ ] **Step 1.2: Run tests to confirm they fail**

```bash
go test ./internal/state/... -run TestSaveScan -v
```

Expected: compilation error (types don't exist yet).

- [ ] **Step 1.3: Create ScanResult model**

Create `internal/model/scan.go`:

```go
package model

import "time"

// ScanResult stores the output of a single Lynis scan.
// Persisted to <stateDir>/scans/<timestamp>.json.
type ScanResult struct {
	Timestamp  time.Time  `json:"timestamp"`
	ReportPath string     `json:"report_path"`
	Score      int        `json:"score"`
	Findings   []*Finding `json:"findings"`
}
```

- [ ] **Step 1.4: Add scan methods to StateManager interface**

In `internal/state/manager.go`, add three methods to the `StateManager` interface:

```go
// SaveScan persists a scan result to <stateDir>/scans/.
SaveScan(ctx context.Context, result *model.ScanResult) error
// LatestScan returns the most recently saved scan result.
// Returns ErrNoScans if no scans have been saved.
LatestScan(ctx context.Context) (*model.ScanResult, error)
// ListScans returns all saved scan results in chronological order.
ListScans(ctx context.Context) ([]*model.ScanResult, error)
```

Also add the sentinel error at the top of the file:

```go
import "errors"

// ErrNoScans is returned by LatestScan when no scans have been saved.
var ErrNoScans = errors.New("no scans found")
```

- [ ] **Step 1.5: Implement scan methods in FileStore**

In `internal/state/store.go`, update `NewFileStore` to also create the `scans` subdirectory. Change:

```go
for _, sub := range []string{"runs", "backups", "locks"} {
```

to:

```go
for _, sub := range []string{"runs", "backups", "locks", "scans"} {
```

Then add three methods after the existing `ListRuns` method:

```go
func (s *FileStore) SaveScan(ctx context.Context, result *model.ScanResult) error {
	_ = ctx
	name := fmt.Sprintf("%d.json", result.Timestamp.UnixNano())
	path := filepath.Join(s.dir, "scans", name)
	return s.writeJSON(path, result)
}

func (s *FileStore) LatestScan(ctx context.Context) (*model.ScanResult, error) {
	scans, err := s.ListScans(ctx)
	if err != nil {
		return nil, err
	}
	if len(scans) == 0 {
		return nil, ErrNoScans
	}
	return scans[len(scans)-1], nil
}

func (s *FileStore) ListScans(ctx context.Context) ([]*model.ScanResult, error) {
	_ = ctx
	dir := filepath.Join(s.dir, "scans")
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var results []*model.ScanResult
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		var result model.ScanResult
		if err := json.Unmarshal(data, &result); err != nil {
			continue
		}
		results = append(results, &result)
	}
	// entries are already sorted lexicographically by ReadDir;
	// since filenames are nanosecond timestamps, this is chronological order.
	return results, nil
}
```

- [ ] **Step 1.6: Run tests**

```bash
go test ./internal/state/... -v
```

Expected: all tests pass including the three new ones.

- [ ] **Step 1.7: Commit**

```bash
git add internal/model/scan.go internal/state/manager.go internal/state/store.go internal/state/store_scan_test.go
git commit -m "feat(hardener): ScanResult model and scan persistence in FileStore"
```

---

## Task 2: Implement LynisScanner.Run()

**Files:**
- Modify: `internal/scanner/lynis/runner.go`

- [ ] **Step 2.1: Write a failing test for Run()**

Create `internal/scanner/lynis/runner_test.go`:

```go
package lynis_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/maestroi/hardener/internal/scanner"
	"github.com/maestroi/hardener/internal/scanner/lynis"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRun_WritesReport(t *testing.T) {
	dir := t.TempDir()
	reportPath := filepath.Join(dir, "lynis-report.dat")
	logPath := filepath.Join(dir, "lynis.log")

	// Write a shell script that acts as a fake lynis binary.
	fakeLynis := filepath.Join(dir, "fake-lynis")
	script := "#!/bin/sh\n# Write a minimal report to --report-file\n" +
		"for arg; do\n  if [ \"$prev\" = \"--report-file\" ]; then\n" +
		"    echo 'hardening_index=55' > \"$arg\"\n" +
		"    echo 'suggestion[]=SSH-7408|Use strong ciphers||'\n" +
		"  fi\n  prev=$arg\ndone\nexit 0\n"
	require.NoError(t, os.WriteFile(fakeLynis, []byte(script), 0755))

	sc := lynis.New(fakeLynis, nil)
	err := sc.Run(context.Background(), scanner.ScanOptions{
		ReportPath: reportPath,
		LogPath:    logPath,
	})
	require.NoError(t, err)
	assert.FileExists(t, reportPath)
}

func TestRun_BinaryNotFound(t *testing.T) {
	sc := lynis.New("/nonexistent/lynis", nil)
	err := sc.Run(context.Background(), scanner.ScanOptions{
		ReportPath: "/tmp/test-report.dat",
	})
	assert.ErrorIs(t, err, lynis.ErrLynisNotFound)
}
```

- [ ] **Step 2.2: Run tests to confirm they fail**

```bash
go test ./internal/scanner/lynis/... -run TestRun -v
```

Expected: compilation error (`ErrLynisNotFound` not defined, `Run` not implemented).

- [ ] **Step 2.3: Implement Run() and ErrLynisNotFound**

Replace the body of `internal/scanner/lynis/runner.go` with:

```go
package lynis

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"time"

	"github.com/maestroi/hardener/internal/model"
	"github.com/maestroi/hardener/internal/scanner"
)

// ErrLynisNotFound is returned when the lynis binary cannot be found or executed.
var ErrLynisNotFound = errors.New("lynis binary not found")

// runTimeout is the maximum time allowed for a Lynis scan.
const runTimeout = 5 * time.Minute

// LynisScanner implements scanner.Scanner using the lynis binary.
type LynisScanner struct {
	binaryPath string
	extraFlags []string
}

// New creates a LynisScanner.
func New(binaryPath string, extraFlags []string) *LynisScanner {
	return &LynisScanner{binaryPath: binaryPath, extraFlags: extraFlags}
}

// Run executes lynis audit system and writes a report to opts.ReportPath.
// Returns ErrLynisNotFound if the binary does not exist or is not executable.
func (s *LynisScanner) Run(ctx context.Context, opts scanner.ScanOptions) error {
	if _, err := exec.LookPath(s.binaryPath); err != nil {
		if _, statErr := os.Stat(s.binaryPath); statErr != nil {
			return fmt.Errorf("%w: %s", ErrLynisNotFound, s.binaryPath)
		}
	}

	reportPath := opts.ReportPath
	if reportPath == "" {
		reportPath = "/var/log/lynis-report.dat"
	}

	args := []string{"audit", "system", "--report-file", reportPath, "--no-colors", "--quiet"}
	args = append(args, s.extraFlags...)

	ctx, cancel := context.WithTimeout(ctx, runTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, s.binaryPath, args...)

	var logW io.Writer = io.Discard
	if opts.LogPath != "" {
		f, err := os.OpenFile(opts.LogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0640)
		if err == nil {
			defer f.Close()
			logW = f
		}
	}
	cmd.Stdout = logW
	cmd.Stderr = logW

	if err := cmd.Run(); err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return fmt.Errorf("lynis timed out after %s", runTimeout)
		}
		return fmt.Errorf("lynis exited non-zero: %w", err)
	}
	return nil
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

- [ ] **Step 2.4: Run tests**

```bash
go test ./internal/scanner/lynis/... -v
```

Expected: all tests pass including `TestRun_WritesReport` and `TestRun_BinaryNotFound`.

- [ ] **Step 2.5: Commit**

```bash
git add internal/scanner/lynis/runner.go internal/scanner/lynis/runner_test.go
git commit -m "feat(hardener): implement LynisScanner.Run() with subprocess and ErrLynisNotFound"
```

---

## Task 3: Wire cmd/audit.go

**Files:**
- Modify: `cmd/audit.go`

- [ ] **Step 3.1: Write a failing integration test**

Create `cmd/audit_test.go`:

```go
package cmd_test

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fixtureReport is a minimal lynis-report.dat content for testing.
const fixtureReport = `
hardening_index=62
suggestion[]=SSH-7408|Enable strong ciphers||
warning[]=AUTH-9262|Set password quality requirements||
`

func runAuditCmd(t *testing.T, args []string, reportContent string) (string, error) {
	t.Helper()
	dir := t.TempDir()
	reportPath := filepath.Join(dir, "lynis-report.dat")
	require.NoError(t, writeFile(t, reportPath, reportContent))

	buf := &bytes.Buffer{}
	cmd := newTestRoot(buf)
	cmd.SetArgs(append([]string{"audit", "--report-path", reportPath, "--state-dir", dir}, args...))
	err := cmd.Execute()
	return buf.String(), err
}

func TestAuditCmd_ParsesReport(t *testing.T) {
	out, err := runAuditCmd(t, nil, fixtureReport)
	require.NoError(t, err)
	assert.Contains(t, out, "SSH-7408")
	assert.Contains(t, out, "62")
}

func TestAuditCmd_JSONOutput(t *testing.T) {
	out, err := runAuditCmd(t, []string{"--output", "json"}, fixtureReport)
	require.NoError(t, err)
	assert.Contains(t, out, `"score"`)
	assert.Contains(t, out, `"SSH-7408"`)
}
```

Add a test helper file `cmd/testhelpers_test.go`:

```go
package cmd_test

import (
	"io"
	"os"
	"testing"

	"github.com/spf13/cobra"
)

func newTestRoot(w io.Writer) *cobra.Command {
	root := &cobra.Command{Use: "hardener"}
	root.PersistentFlags().String("state-dir", "/var/lib/hardener", "")
	root.PersistentFlags().String("profile", "server", "")
	root.PersistentFlags().String("output", "table", "")
	root.PersistentFlags().String("config", "", "")
	root.PersistentFlags().Bool("verbose", false, "")
	root.SetOut(w)
	root.AddCommand(newAuditCmd(w))
	return root
}

func writeFile(t *testing.T, path, content string) error {
	t.Helper()
	return os.WriteFile(path, []byte(content), 0644)
}
```

- [ ] **Step 3.2: Run tests to confirm they fail**

```bash
go test ./cmd/... -run TestAuditCmd -v
```

Expected: compilation error (functions not yet defined).

- [ ] **Step 3.3: Implement cmd/audit.go**

Replace `cmd/audit.go` with:

```go
package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/maestroi/hardener/internal/config"
	"github.com/maestroi/hardener/internal/model"
	"github.com/maestroi/hardener/internal/reporter"
	"github.com/maestroi/hardener/internal/scanner"
	"github.com/maestroi/hardener/internal/scanner/lynis"
	"github.com/maestroi/hardener/internal/state"
)

var auditFresh bool
var auditReportPath string

var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Run Lynis and display findings + current hardening score",
	RunE:  runAudit,
}

func init() {
	auditCmd.Flags().BoolVar(&auditFresh, "fresh", false, "force a new Lynis scan even if a cached scan exists")
	auditCmd.Flags().StringVar(&auditReportPath, "report-path", "", "parse a specific report file (skips subprocess)")
	rootCmd.AddCommand(auditCmd)
}

func newAuditCmd(w io.Writer) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Run Lynis and display findings + current hardening score",
	}
	cmd.Flags().Bool("fresh", false, "force a new Lynis scan")
	cmd.Flags().String("report-path", "", "parse a specific report file")
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		return runAuditWith(cmd, w)
	}
	return cmd
}

func runAudit(cmd *cobra.Command, _ []string) error {
	return runAuditWith(cmd, cmd.OutOrStdout())
}

func runAuditWith(cmd *cobra.Command, w io.Writer) error {
	ctx := context.Background()

	var cfgBytes []byte
	var err error
	cfgFlag, _ := cmd.Flags().GetString("config")
	if cfgFlag == "" {
		cfgFlag = flagConfig
	}
	if cfgFlag != "" {
		cfgBytes, err = os.ReadFile(cfgFlag)
		if err != nil {
			return fmt.Errorf("reading config: %w", err)
		}
	}

	cfg, err := config.LoadConfigFromBytes(cfgBytes)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	if sd, _ := cmd.Flags().GetString("state-dir"); sd != "" {
		cfg.StateDir = sd
	} else if flagStateDir != "" {
		cfg.StateDir = flagStateDir
	}

	var rep reporter.Reporter
	outFlag, _ := cmd.Flags().GetString("output")
	if outFlag == "" {
		outFlag = flagOutput
	}
	switch outFlag {
	case "json":
		rep = reporter.NewJSONReporter(w)
	default:
		rep = reporter.NewTerminalReporter(w)
	}

	store, err := state.NewFileStore(cfg.StateDir)
	if err != nil {
		return fmt.Errorf("opening state store: %w", err)
	}

	sc := lynis.New(cfg.Lynis.Binary, cfg.Lynis.ExtraFlags)

	reportPath, _ := cmd.Flags().GetString("report-path")
	if reportPath == "" {
		reportPath = auditReportPath
	}

	// If --report-path given, parse directly without subprocess.
	if reportPath != "" {
		return parseAndDisplay(ctx, sc, store, rep, reportPath)
	}

	// Try to run Lynis as subprocess.
	runReportPath := filepath.Join(cfg.StateDir, fmt.Sprintf("lynis-%d.dat", time.Now().UnixNano()))
	runErr := sc.Run(ctx, scanner.ScanOptions{
		ReportPath: runReportPath,
		LogPath:    cfg.Lynis.LogPath,
	})

	if runErr != nil {
		if errors.Is(runErr, lynis.ErrLynisNotFound) {
			// Fall back to latest cached scan.
			cached, cacheErr := store.LatestScan(ctx)
			if cacheErr != nil {
				return fmt.Errorf("lynis not found and no cached scan available: %w", cacheErr)
			}
			fmt.Fprintf(w, "[warn] lynis not found, using cached scan from %s\n",
				cached.Timestamp.Format("2006-01-02 15:04:05"))
			return rep.Audit(ctx, cached.Findings, cached.Score)
		}
		return fmt.Errorf("running lynis: %w", runErr)
	}

	return parseAndDisplay(ctx, sc, store, rep, runReportPath)
}

func parseAndDisplay(ctx context.Context, sc *lynis.LynisScanner, store *state.FileStore, rep reporter.Reporter, reportPath string) error {
	findings, err := sc.ParseReport(ctx, reportPath)
	if err != nil {
		return fmt.Errorf("parsing report %s: %w", reportPath, err)
	}

	score, _ := sc.Score(ctx, reportPath)

	result := &model.ScanResult{
		Timestamp:  time.Now().UTC(),
		ReportPath: reportPath,
		Score:      score,
		Findings:   findings,
	}
	if err := store.SaveScan(ctx, result); err != nil {
		// Non-fatal: persist failure shouldn't block displaying results.
		fmt.Fprintf(os.Stderr, "[warn] failed to save scan result: %v\n", err)
	}

	return rep.Audit(ctx, findings, score)
}
```

- [ ] **Step 3.4: Run tests**

```bash
go test ./cmd/... -run TestAuditCmd -v
```

Expected: both tests pass.

- [ ] **Step 3.5: Build and smoke-test**

```bash
go build ./... && echo "Build OK"
```

Expected: no errors.

- [ ] **Step 3.6: Commit**

```bash
git add cmd/audit.go cmd/audit_test.go cmd/testhelpers_test.go
git commit -m "feat(hardener): implement audit command — subprocess, fallback, parse, persist"
```

---

## Task 4: Full test suite check

- [ ] **Step 4.1: Run all tests**

```bash
go test ./... -v 2>&1 | tail -30
```

Expected: all tests pass.

- [ ] **Step 4.2: Commit if anything was fixed**

If any tests needed adjustment, commit the fixes:

```bash
git add -p
git commit -m "fix: test suite cleanup after audit command"
```
