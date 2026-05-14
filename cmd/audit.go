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

	var rep reporter.Reporter
	switch flagOutput {
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

	if reportPath != "" {
		return parseAndDisplay(ctx, sc, store, rep, reportPath)
	}

	runReportPath := filepath.Join(cfg.StateDir, fmt.Sprintf("lynis-%d.dat", time.Now().UnixNano()))
	runErr := sc.Run(ctx, scanner.ScanOptions{
		ReportPath: runReportPath,
		LogPath:    cfg.Lynis.LogPath,
	})

	if runErr != nil {
		if errors.Is(runErr, lynis.ErrLynisNotFound) {
			fresh, _ := cmd.Flags().GetBool("fresh")
			if fresh {
				return fmt.Errorf("lynis not available and --fresh was set: %w", runErr)
			}
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
		fmt.Fprintf(os.Stderr, "[warn] failed to save scan result: %v\n", err)
	}

	return rep.Audit(ctx, findings, score)
}
