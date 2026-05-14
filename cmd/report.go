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

	var cfgBytes []byte
	var err error
	if flagConfig != "" {
		cfgBytes, err = os.ReadFile(flagConfig)
		if err != nil {
			return fmt.Errorf("reading config: %w", err)
		}
	}

	cfg, err := config.LoadConfigFromBytes(cfgBytes)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	if flagStateDir != "" {
		cfg.StateDir = flagStateDir
	}

	useJSON := flagOutput == "json"

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
	run, err := store.GetRun(ctx, runID)
	if err != nil {
		return fmt.Errorf("run %s not found: %w", runID, err)
	}

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
		report.LiveAvailable = false
		if errors.Is(runErr, lynis.ErrLynisNotFound) {
			report.LiveWarn = fmt.Sprintf("live comparison unavailable: %v", runErr)
		} else {
			report.LiveWarn = fmt.Sprintf("live comparison unavailable: lynis exited with error: %v", runErr)
		}
	} else {
		currentFindings, parseErr := sc.ParseReport(ctx, tmpReport)
		if parseErr != nil {
			report.LiveAvailable = false
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
		// Without a live scan we can only show plan-derived data.
		for _, a := range plan {
			if !a.Applicable {
				report.Skipped = append(report.Skipped, a.FindingID)
			} else {
				report.StillOpen = append(report.StillOpen, a.FindingID)
			}
		}
		report.Fixed = []string{}
		report.New = []string{}
	}

	if useJSON {
		return renderComplianceJSON(ctx, w, report)
	}
	return renderComplianceTable(ctx, w, report)
}
