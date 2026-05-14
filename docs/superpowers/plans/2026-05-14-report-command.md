# report command Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement `hardener report` (run history table) and `hardener report --run-id <id>` (compliance drill-down: stored plan vs live Lynis re-scan).

**Architecture:** Two new `StateManager` methods (`LoadPlan`, `LoadApplied`) read existing per-run JSON files. History mode wires `ListRuns → History()`. Drill-down re-runs Lynis into a temp file, compares finding IDs against the stored plan, and emits a `complianceReport` struct rendered as table or JSON. Lynis unavailability degrades gracefully — stored data is shown with a `[warn]` notice.

**Tech Stack:** Go 1.22, `github.com/maestroi/hardener`, `github.com/spf13/cobra`, testify.

---

## File Map

| File | Action | Purpose |
|------|--------|---------|
| `internal/state/manager.go` | Modify | Add `LoadPlan`, `LoadApplied` to interface |
| `internal/state/store.go` | Modify | Implement the two new load methods |
| `internal/state/store_report_test.go` | Create | Unit tests for `LoadPlan` / `LoadApplied` round-trips |
| `cmd/report.go` | Modify | Full implementation: history mode + drill-down mode |
| `cmd/compliance.go` | Create | `compareFindings` logic + `complianceReport` struct |
| `cmd/compliance_test.go` | Create | Unit tests for compliance comparison (no subprocess) |
| `cmd/report_test.go` | Create | Integration tests for both `report` modes |
| `cmd/testhelpers_test.go` | Modify | Add `newReportCmd` to `newTestRoot` |

---

## Task 1: Add LoadPlan and LoadApplied to StateManager + FileStore

**Files:**
- Modify: `internal/state/manager.go`
- Modify: `internal/state/store.go`
- Create: `internal/state/store_report_test.go`

The files `plan.json` and `applied.json` already exist per-run (written by `SavePlan` / `RecordApplied`). These are pure reads.

- [ ] **Step 1.1: Write failing tests**

Create `internal/state/store_report_test.go`:

```go
package state_test

import (
	"context"
	"testing"
	"time"

	"github.com/maestroi/hardener/internal/model"
	"github.com/maestroi/hardener/internal/state"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadPlan_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	store, err := state.NewFileStore(dir)
	require.NoError(t, err)

	ctx := context.Background()
	run, err := store.InitRun(ctx, "test-profile", false)
	require.NoError(t, err)

	actions := []*model.PlannedAction{
		{FindingID: "SSH-7408", ModuleID: "ssh-ciphers", Applicable: true, Risk: model.RiskLow},
		{FindingID: "AUTH-9262", ModuleID: "pam-pwquality", Applicable: false, SkipReason: "already compliant"},
	}
	require.NoError(t, store.SavePlan(ctx, run.ID, actions))

	loaded, err := store.LoadPlan(ctx, run.ID)
	require.NoError(t, err)
	require.Len(t, loaded, 2)
	assert.Equal(t, "SSH-7408", loaded[0].FindingID)
	assert.True(t, loaded[0].Applicable)
	assert.Equal(t, "AUTH-9262", loaded[1].FindingID)
	assert.False(t, loaded[1].Applicable)
}

func TestLoadApplied_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	store, err := state.NewFileStore(dir)
	require.NoError(t, err)

	ctx := context.Background()
	run, err := store.InitRun(ctx, "test-profile", false)
	require.NoError(t, err)

	action := &model.AppliedAction{
		PlannedAction: model.PlannedAction{FindingID: "SSH-7408", ModuleID: "ssh-ciphers"},
		AppliedAt:     time.Now().UTC(),
		Status:        model.ActionApplied,
	}
	require.NoError(t, store.RecordApplied(ctx, run.ID, action))

	loaded, err := store.LoadApplied(ctx, run.ID)
	require.NoError(t, err)
	require.Len(t, loaded, 1)
	assert.Equal(t, "SSH-7408", loaded[0].FindingID)
	assert.Equal(t, model.ActionApplied, loaded[0].Status)
}

func TestLoadPlan_RunNotFound(t *testing.T) {
	dir := t.TempDir()
	store, err := state.NewFileStore(dir)
	require.NoError(t, err)

	_, err = store.LoadPlan(context.Background(), "nonexistent-run")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "nonexistent-run")
}
```

- [ ] **Step 1.2: Run tests to confirm they fail**

```bash
go test ./internal/state/... -run TestLoadPlan -v
go test ./internal/state/... -run TestLoadApplied -v
```

Expected: compilation error (`LoadPlan`, `LoadApplied` not defined).

- [ ] **Step 1.3: Add methods to StateManager interface**

In `internal/state/manager.go`, add two methods to the `StateManager` interface:

```go
// LoadPlan loads the planned actions for a given run.
LoadPlan(ctx context.Context, runID string) ([]*model.PlannedAction, error)
// LoadApplied loads the applied actions for a given run.
LoadApplied(ctx context.Context, runID string) ([]*model.AppliedAction, error)
```

- [ ] **Step 1.4: Implement LoadPlan and LoadApplied in FileStore**

In `internal/state/store.go`, add after the `LoadRollbackManifest` method:

```go
func (s *FileStore) LoadPlan(ctx context.Context, runID string) ([]*model.PlannedAction, error) {
	_ = ctx
	path := filepath.Join(s.runDir(runID), "plan.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("plan for run %s: %w", runID, err)
	}
	var actions []*model.PlannedAction
	if err := json.Unmarshal(data, &actions); err != nil {
		return nil, fmt.Errorf("parsing plan for run %s: %w", runID, err)
	}
	return actions, nil
}

func (s *FileStore) LoadApplied(ctx context.Context, runID string) ([]*model.AppliedAction, error) {
	_ = ctx
	path := filepath.Join(s.runDir(runID), "applied.json")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("applied actions for run %s: %w", runID, err)
	}
	var actions []*model.AppliedAction
	if err := json.Unmarshal(data, &actions); err != nil {
		return nil, fmt.Errorf("parsing applied actions for run %s: %w", runID, err)
	}
	return actions, nil
}
```

- [ ] **Step 1.5: Run tests**

```bash
go test ./internal/state/... -v
```

Expected: all tests pass including the three new ones.

- [ ] **Step 1.6: Commit**

```bash
git add internal/state/manager.go internal/state/store.go internal/state/store_report_test.go
git commit -m "feat(hardener): add LoadPlan and LoadApplied to StateManager"
```

---

## Task 2: Compliance comparison logic

**Files:**
- Create: `cmd/compliance.go`
- Create: `cmd/compliance_test.go`

The compliance logic is pure data transformation — no I/O, no subprocess. A `complianceReport` struct holds finding IDs bucketed into fixed / still-open / skipped / new. This lives in the `cmd` package so it can access `model` types without creating a new package.

- [ ] **Step 2.1: Write failing unit tests**

Create `cmd/compliance_test.go`:

```go
package cmd

import (
	"testing"

	"github.com/maestroi/hardener/internal/model"
	"github.com/stretchr/testify/assert"
)

func makeAction(findingID string, applicable bool) *model.PlannedAction {
	return &model.PlannedAction{
		FindingID:  findingID,
		ModuleID:   "test-module",
		Applicable: applicable,
	}
}

func makeFinding(id string) *model.Finding {
	return &model.Finding{ID: id, Category: model.CategoryFromID(id)}
}

func TestCompareFindings_Fixed(t *testing.T) {
	plan := []*model.PlannedAction{
		makeAction("SSH-7408", true),  // applicable — was targeted
		makeAction("AUTH-9262", true), // applicable — was targeted
	}
	// SSH-7408 is now absent from the current scan = fixed
	current := []*model.Finding{makeFinding("AUTH-9262")}

	report := compareFindings(plan, current)
	assert.Equal(t, []string{"SSH-7408"}, report.Fixed)
	assert.Equal(t, []string{"AUTH-9262"}, report.StillOpen)
	assert.Empty(t, report.Skipped)
	assert.Empty(t, report.New)
}

func TestCompareFindings_Skipped(t *testing.T) {
	plan := []*model.PlannedAction{
		makeAction("PKGS-7370", false), // not applicable — was skipped
	}
	current := []*model.Finding{}

	report := compareFindings(plan, current)
	assert.Empty(t, report.Fixed)
	assert.Empty(t, report.StillOpen)
	assert.Equal(t, []string{"PKGS-7370"}, report.Skipped)
	assert.Empty(t, report.New)
}

func TestCompareFindings_New(t *testing.T) {
	plan := []*model.PlannedAction{
		makeAction("SSH-7408", true),
	}
	// KRNL-6000 is in the current scan but was not in the stored plan at all
	current := []*model.Finding{
		makeFinding("SSH-7408"),
		makeFinding("KRNL-6000"),
	}

	report := compareFindings(plan, current)
	assert.Empty(t, report.Fixed)
	assert.Equal(t, []string{"SSH-7408"}, report.StillOpen)
	assert.Empty(t, report.Skipped)
	assert.Equal(t, []string{"KRNL-6000"}, report.New)
}

func TestCompareFindings_Mixed(t *testing.T) {
	plan := []*model.PlannedAction{
		makeAction("SSH-7408", true),   // fixed
		makeAction("AUTH-9262", true),  // still open
		makeAction("PKGS-7370", false), // skipped
	}
	current := []*model.Finding{
		makeFinding("AUTH-9262"), // still open
		makeFinding("LOGG-2154"), // new
	}

	report := compareFindings(plan, current)
	assert.Equal(t, []string{"SSH-7408"}, report.Fixed)
	assert.Equal(t, []string{"AUTH-9262"}, report.StillOpen)
	assert.Equal(t, []string{"PKGS-7370"}, report.Skipped)
	assert.Equal(t, []string{"LOGG-2154"}, report.New)
}
```

- [ ] **Step 2.2: Run tests to confirm they fail**

```bash
go test ./cmd/... -run TestCompareFindings -v
```

Expected: compilation error (`compareFindings`, `complianceReport` not defined).

- [ ] **Step 2.3: Implement compliance.go**

Create `cmd/compliance.go`:

```go
package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/maestroi/hardener/internal/model"
)

// complianceReport is the result of comparing a stored plan against the current Lynis scan.
type complianceReport struct {
	RunID        string   `json:"run_id"`
	StoredScore  int      `json:"stored_score"`
	CurrentScore int      `json:"current_score"`
	Fixed        []string `json:"fixed"`     // finding IDs that were applicable, now absent
	StillOpen    []string `json:"still_open"` // finding IDs that were applicable, still present
	Skipped      []string `json:"skipped"`    // finding IDs that were not applicable in stored plan
	New          []string `json:"new"`        // finding IDs in current scan not in stored plan
	LiveAvailable bool    `json:"live_available"`
	LiveWarn     string   `json:"live_warn,omitempty"`
}

// compareFindings computes a complianceReport from the stored plan and the current scan findings.
func compareFindings(plan []*model.PlannedAction, current []*model.Finding) *complianceReport {
	currentIDs := make(map[string]bool, len(current))
	for _, f := range current {
		currentIDs[f.ID] = true
	}

	plannedIDs := make(map[string]bool, len(plan))
	for _, a := range plan {
		plannedIDs[a.FindingID] = true
	}

	report := &complianceReport{
		Fixed:     []string{},
		StillOpen: []string{},
		Skipped:   []string{},
		New:       []string{},
	}

	for _, a := range plan {
		if !a.Applicable {
			report.Skipped = append(report.Skipped, a.FindingID)
			continue
		}
		if currentIDs[a.FindingID] {
			report.StillOpen = append(report.StillOpen, a.FindingID)
		} else {
			report.Fixed = append(report.Fixed, a.FindingID)
		}
	}

	for _, f := range current {
		if !plannedIDs[f.ID] {
			report.New = append(report.New, f.ID)
		}
	}

	return report
}

// renderComplianceTable writes a human-readable compliance summary to w.
func renderComplianceTable(_ context.Context, w io.Writer, r *complianceReport) error {
	fmt.Fprintf(w, "\nCompliance report for run %s\n", r.RunID)
	if r.LiveWarn != "" {
		fmt.Fprintf(w, "[warn] %s\n", r.LiveWarn)
	}
	if r.LiveAvailable {
		fmt.Fprintf(w, "Score: %d → %d\n", r.StoredScore, r.CurrentScore)
	} else {
		fmt.Fprintf(w, "Score at run time: %d  (live score unavailable)\n", r.StoredScore)
	}
	fmt.Fprintln(w)

	printSection := func(label string, ids []string) {
		fmt.Fprintf(w, "  %-12s %d\n", label+":", len(ids))
		for _, id := range ids {
			fmt.Fprintf(w, "    - %s\n", id)
		}
	}

	printSection("Fixed", r.Fixed)
	printSection("Still open", r.StillOpen)
	printSection("Skipped", r.Skipped)
	printSection("New", r.New)
	return nil
}

// renderComplianceJSON writes a JSON compliance summary to w.
func renderComplianceJSON(_ context.Context, w io.Writer, r *complianceReport) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}
```

- [ ] **Step 2.4: Run tests**

```bash
go test ./cmd/... -run TestCompareFindings -v
```

Expected: all four tests pass.

- [ ] **Step 2.5: Commit**

```bash
git add cmd/compliance.go cmd/compliance_test.go
git commit -m "feat(hardener): compliance comparison logic for report drill-down"
```

---

## Task 3: Wire cmd/report.go

**Files:**
- Modify: `cmd/report.go`
- Create: `cmd/report_test.go`
- Modify: `cmd/testhelpers_test.go`

- [ ] **Step 3.1: Write failing integration tests**

Create `cmd/report_test.go`:

```go
package cmd_test

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/maestroi/hardener/internal/model"
	"github.com/maestroi/hardener/internal/state"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupRunWithPlan(t *testing.T, stateDir string) string {
	t.Helper()
	store, err := state.NewFileStore(stateDir)
	require.NoError(t, err)

	ctx := context.Background()
	run, err := store.InitRun(ctx, "test-profile", false)
	require.NoError(t, err)

	run.ScoreBefore = 40
	run.ScoreAfter = 55

	actions := []*model.PlannedAction{
		{FindingID: "SSH-7408", ModuleID: "ssh-ciphers", Applicable: true, Risk: model.RiskLow},
		{FindingID: "AUTH-9262", ModuleID: "pam-pwquality", Applicable: false, SkipReason: "already compliant"},
	}
	require.NoError(t, store.SavePlan(ctx, run.ID, actions))

	applied := &model.AppliedAction{
		PlannedAction: *actions[0],
		AppliedAt:     time.Now().UTC(),
		Status:        model.ActionApplied,
	}
	require.NoError(t, store.RecordApplied(ctx, run.ID, applied))
	require.NoError(t, store.CompleteRun(ctx, run.ID, model.RunComplete))

	return run.ID
}

func TestReportCmd_History(t *testing.T) {
	dir := t.TempDir()
	setupRunWithPlan(t, dir)

	buf := &bytes.Buffer{}
	cmd := newTestRoot(buf)
	cmd.SetArgs([]string{"report", "--state-dir", dir})
	err := cmd.Execute()
	require.NoError(t, err)
	// History table shows the run
	assert.Contains(t, buf.String(), "SSH")
}

func TestReportCmd_History_NoRuns(t *testing.T) {
	dir := t.TempDir()

	buf := &bytes.Buffer{}
	cmd := newTestRoot(buf)
	cmd.SetArgs([]string{"report", "--state-dir", dir})
	err := cmd.Execute()
	require.NoError(t, err)
	assert.Contains(t, buf.String(), "No runs found.")
}

func TestReportCmd_DrillDown_NoLynis(t *testing.T) {
	dir := t.TempDir()
	runID := setupRunWithPlan(t, dir)

	// Use a nonexistent lynis binary so the command degrades gracefully.
	buf := &bytes.Buffer{}
	cmd := newTestRoot(buf)
	cmd.SetArgs([]string{"report", "--state-dir", dir, "--run-id", runID, "--lynis-binary", "/nonexistent/lynis"})
	err := cmd.Execute()
	require.NoError(t, err)
	out := buf.String()
	assert.Contains(t, out, "live comparison unavailable")
	assert.Contains(t, out, runID)
}

func TestReportCmd_DrillDown_JSONOutput(t *testing.T) {
	dir := t.TempDir()
	runID := setupRunWithPlan(t, dir)

	buf := &bytes.Buffer{}
	cmd := newTestRoot(buf)
	cmd.SetArgs([]string{"report", "--state-dir", dir, "--run-id", runID,
		"--lynis-binary", "/nonexistent/lynis", "--output", "json"})
	err := cmd.Execute()
	require.NoError(t, err)

	var cr struct {
		RunID string `json:"run_id"`
	}
	require.NoError(t, json.Unmarshal(buf.Bytes(), &cr))
	assert.Equal(t, runID, cr.RunID)
}

func TestReportCmd_DrillDown_RunNotFound(t *testing.T) {
	dir := t.TempDir()

	buf := &bytes.Buffer{}
	cmd := newTestRoot(buf)
	cmd.SetArgs([]string{"report", "--state-dir", dir, "--run-id", "nonexistent"})
	err := cmd.Execute()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "nonexistent")
}
```

- [ ] **Step 3.2: Update testhelpers_test.go to include the report command**

In `cmd/testhelpers_test.go`, modify `newTestRoot` to also register `newReportCmd(w)`:

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
	root.AddCommand(newReportCmd(w))
	return root
}

func writeFile(t *testing.T, path, content string) error {
	t.Helper()
	return os.WriteFile(path, []byte(content), 0644)
}
```

- [ ] **Step 3.3: Run tests to confirm they fail**

```bash
go test ./cmd/... -run TestReportCmd -v
```

Expected: compilation error (`newReportCmd` not defined).

- [ ] **Step 3.4: Implement cmd/report.go**

Replace `cmd/report.go` with:

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
	"github.com/maestroi/hardener/internal/reporter"
	"github.com/maestroi/hardener/internal/scanner"
	"github.com/maestroi/hardener/internal/scanner/lynis"
	"github.com/maestroi/hardener/internal/state"
)

var reportRunID string

var reportCmd = &cobra.Command{
	Use:   "report",
	Short: "Show run history and before/after scores",
	RunE:  runReport,
}

func init() {
	reportCmd.Flags().StringVar(&reportRunID, "run-id", "", "drill into a single run")
	reportCmd.Flags().String("lynis-binary", "", "override lynis binary path (for testing)")
	rootCmd.AddCommand(reportCmd)
}

func newReportCmd(w io.Writer) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "report",
		Short: "Show run history and before/after scores",
	}
	cmd.Flags().String("run-id", "", "drill into a single run")
	cmd.Flags().String("lynis-binary", "", "override lynis binary path")
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		return runReportWith(cmd, w)
	}
	return cmd
}

func runReport(cmd *cobra.Command, _ []string) error {
	return runReportWith(cmd, cmd.OutOrStdout())
}

func runReportWith(cmd *cobra.Command, w io.Writer) error {
	ctx := context.Background()

	cfg, err := loadConfig(cmd)
	if err != nil {
		return err
	}

	outFlag, _ := cmd.Flags().GetString("output")
	if outFlag == "" {
		outFlag = flagOutput
	}

	useJSON := outFlag == "json"

	store, err := state.NewFileStore(cfg.StateDir)
	if err != nil {
		return fmt.Errorf("opening state store: %w", err)
	}

	runID, _ := cmd.Flags().GetString("run-id")
	if runID == "" {
		runID = reportRunID
	}

	if runID == "" {
		return runHistory(ctx, store, w, useJSON)
	}
	return runDrillDown(ctx, cmd, store, cfg, w, runID, useJSON)
}

func runHistory(ctx context.Context, store *state.FileStore, w io.Writer, useJSON bool) error {
	runs, err := store.ListRuns(ctx)
	if err != nil {
		return fmt.Errorf("listing runs: %w", err)
	}

	var rep reporter.Reporter
	if useJSON {
		rep = reporter.NewJSONReporter(w)
	} else {
		rep = reporter.NewTerminalReporter(w)
	}
	return rep.History(ctx, runs)
}

func runDrillDown(ctx context.Context, cmd *cobra.Command, store *state.FileStore, cfg *config.Config, w io.Writer, runID string, useJSON bool) error {
	// Load stored run metadata.
	run, err := store.GetRun(ctx, runID)
	if err != nil {
		return fmt.Errorf("run %s not found: %w", runID, err)
	}

	// Load stored plan.
	plan, err := store.LoadPlan(ctx, runID)
	if err != nil {
		return fmt.Errorf("loading plan for run %s: %w", runID, err)
	}

	report := &complianceReport{
		RunID:       runID,
		StoredScore: run.ScoreAfter,
		Fixed:       []string{},
		StillOpen:   []string{},
		Skipped:     []string{},
		New:         []string{},
	}

	// Attempt live Lynis re-scan.
	binaryOverride, _ := cmd.Flags().GetString("lynis-binary")
	binaryPath := cfg.Lynis.Binary
	if binaryOverride != "" {
		binaryPath = binaryOverride
	}

	sc := lynis.New(binaryPath, cfg.Lynis.ExtraFlags)
	tmpReport := filepath.Join(cfg.StateDir, fmt.Sprintf("compliance-%d.dat", time.Now().UnixNano()))
	defer os.Remove(tmpReport)

	runErr := sc.Run(ctx, scanner.ScanOptions{ReportPath: tmpReport})
	if runErr != nil {
		if errors.Is(runErr, lynis.ErrLynisNotFound) {
			report.LiveAvailable = false
			report.LiveWarn = fmt.Sprintf("live comparison unavailable: %v", runErr)
		} else {
			report.LiveAvailable = false
			report.LiveWarn = fmt.Sprintf("live comparison unavailable: lynis exited with error: %v", runErr)
		}
	} else {
		currentFindings, parseErr := sc.ParseReport(ctx, tmpReport)
		if parseErr != nil {
			report.LiveWarn = fmt.Sprintf("live comparison unavailable: parsing report: %v", parseErr)
		} else {
			report.LiveAvailable = true
			currentScore, _ := sc.Score(ctx, tmpReport)
			report.CurrentScore = currentScore
			result := compareFindings(plan, currentFindings)
			report.Fixed = result.Fixed
			report.StillOpen = result.StillOpen
			report.Skipped = result.Skipped
			report.New = result.New
		}
	}

	if !report.LiveAvailable && len(plan) > 0 {
		// Populate from stored plan so the output is still useful.
		stored := compareFindings(plan, nil)
		report.Skipped = stored.Skipped
		// All applicable findings are "still open" when we can't verify.
		report.StillOpen = stored.Fixed // compareFindings with nil current puts applicable→fixed; invert
		report.Fixed = []string{}
	}

	if useJSON {
		return renderComplianceJSON(ctx, w, report)
	}
	return renderComplianceTable(ctx, w, report)
}

// loadConfig reads flag values and returns a populated config.Config.
func loadConfig(cmd *cobra.Command) (*config.Config, error) {
	var cfgBytes []byte
	cfgFlag, _ := cmd.Flags().GetString("config")
	if cfgFlag == "" {
		cfgFlag = flagConfig
	}
	if cfgFlag != "" {
		var err error
		cfgBytes, err = os.ReadFile(cfgFlag)
		if err != nil {
			return nil, fmt.Errorf("reading config: %w", err)
		}
	}

	cfg, err := config.LoadConfigFromBytes(cfgBytes)
	if err != nil {
		return nil, fmt.Errorf("loading config: %w", err)
	}

	if sd, _ := cmd.Flags().GetString("state-dir"); sd != "" {
		cfg.StateDir = sd
	} else if flagStateDir != "" {
		cfg.StateDir = flagStateDir
	}
	return cfg, nil
}
```

- [ ] **Step 3.5: Fix the "no live scan" still-open logic**

The `runDrillDown` code above has a flaw: `compareFindings(plan, nil)` with `nil` current will put all applicable findings in `Fixed` (since no IDs exist in `currentIDs`). We need to put them in `StillOpen`. Fix the fallback block in `runDrillDown`:

Replace the fallback block:

```go
	if !report.LiveAvailable && len(plan) > 0 {
		// Populate from stored plan so the output is still useful.
		stored := compareFindings(plan, nil)
		report.Skipped = stored.Skipped
		// All applicable findings are "still open" when we can't verify.
		report.StillOpen = stored.Fixed // compareFindings with nil current puts applicable→fixed; invert
		report.Fixed = []string{}
	}
```

with:

```go
	if !report.LiveAvailable && len(plan) > 0 {
		// Without a live scan we can only show plan-derived data.
		for _, a := range plan {
			if !a.Applicable {
				report.Skipped = append(report.Skipped, a.FindingID)
			} else {
				// Treat all applicable findings as unknown (still open) — we can't verify.
				report.StillOpen = append(report.StillOpen, a.FindingID)
			}
		}
		report.Fixed = []string{}
		report.New = []string{}
	}
```

- [ ] **Step 3.6: Run tests**

```bash
go test ./cmd/... -run TestReportCmd -v
```

Expected: all five report tests pass.

- [ ] **Step 3.7: Build**

```bash
go build ./... && echo "Build OK"
```

Expected: no errors.

- [ ] **Step 3.8: Commit**

```bash
git add cmd/report.go cmd/report_test.go cmd/testhelpers_test.go
git commit -m "feat(hardener): implement report command — history mode and compliance drill-down"
```

---

## Task 4: Full test suite check

- [ ] **Step 4.1: Run all tests**

```bash
go test ./... -v 2>&1 | tail -40
```

Expected: all tests pass.

- [ ] **Step 4.2: Smoke-test history mode**

```bash
go build -o /tmp/hardener . && /tmp/hardener report --help
```

Expected: usage output with `--run-id` and `--output` flags visible.

- [ ] **Step 4.3: Commit if anything needed fixing**

If any tests needed adjustment:

```bash
git add -p
git commit -m "fix: test suite cleanup after report command"
```
