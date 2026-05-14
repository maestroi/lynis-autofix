package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/maestroi/hardener/internal/config"
	"github.com/maestroi/hardener/internal/executor"
	"github.com/maestroi/hardener/internal/planner"
	"github.com/maestroi/hardener/internal/registry"
	"github.com/maestroi/hardener/internal/reporter"
	"github.com/maestroi/hardener/internal/safety"
	"github.com/maestroi/hardener/internal/scanner/lynis"
)

var (
	planFresh            bool
	planDryRun           bool
	planConfirmDangerous bool
	planFindings         []string
	planModules          []string
)

var planCmd = &cobra.Command{
	Use:   "plan",
	Short: "Show remediation plan without applying anything",
	RunE:  runPlan,
}

func init() {
	planCmd.Flags().BoolVar(&planFresh, "fresh", false, "run Lynis scan before planning (not implemented)")
	planCmd.Flags().BoolVar(&planDryRun, "dry-run", false, "alias for plan-only mode (plan never mutates)")
	planCmd.Flags().BoolVar(&planConfirmDangerous, "confirm-dangerous", false, "show Dangerous=true actions as applicable (default: list them as skipped)")
	planCmd.Flags().StringSliceVar(&planFindings, "finding", nil, "limit to finding IDs")
	planCmd.Flags().StringSliceVar(&planModules, "module", nil, "limit to module IDs")
	rootCmd.AddCommand(planCmd)
}

func runPlan(cmd *cobra.Command, args []string) error {
	_ = args
	ctx := context.Background()

	var cfgBytes []byte
	var err error
	if flagConfig != "" {
		cfgBytes, err = os.ReadFile(flagConfig)
		if err != nil {
			return fmt.Errorf("reading config file: %w", err)
		}
	}

	cfg, err := config.LoadConfigFromBytes(cfgBytes)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}
	if flagStateDir != "" {
		cfg.StateDir = flagStateDir
	}
	if flagProfile != "" {
		cfg.Profile = flagProfile
	}

	if planFresh {
		fmt.Fprintln(cmd.ErrOrStderr(), "[warn] --fresh is not implemented yet; using existing report.")
	}

	profile, err := config.LoadBundledProfile(cfg.Profile)
	if err != nil {
		return fmt.Errorf("loading profile %q: %w", cfg.Profile, err)
	}

	localInspect := executor.NewLocalExecutor()

	var rep reporter.Reporter
	switch flagOutput {
	case "json":
		rep = reporter.NewJSONReporter(cmd.OutOrStdout())
	default:
		rep = reporter.NewTerminalReporter(cmd.OutOrStdout())
	}

	sc := lynis.New(cfg.Lynis.Binary, cfg.Lynis.ExtraFlags)
	findings, err := sc.ParseReport(ctx, cfg.Lynis.ReportPath)
	if err != nil {
		return fmt.Errorf("parsing Lynis report %s: %w", cfg.Lynis.ReportPath, err)
	}

	reg := registry.Default()
	findings = filterFindings(findings, reg, planFindings, planModules)

	p := planner.New(reg, localInspect)
	actions, err := p.Plan(ctx, findings, profile)
	if err != nil {
		return fmt.Errorf("planning: %w", err)
	}

	checkers := []safety.Checker{
		safety.NewProfileFilter(profile),
		safety.NewRiskFilter(profile),
		safety.NewSSHChecker(),
	}
	for _, action := range actions {
		if !action.Applicable {
			continue
		}
		result, err := safety.RunAll(ctx, checkers, action, localInspect)
		if err != nil {
			return fmt.Errorf("safety check for %s: %w", action.FindingID, err)
		}
		if !result.Safe {
			action.Applicable = false
			action.SkipReason = result.Reason
		}
	}

	confirmDangerous := planConfirmDangerous || cfg.ConfirmDangerous
	for _, action := range actions {
		if !action.Applicable {
			continue
		}
		if action.Dangerous && !confirmDangerous {
			action.Applicable = false
			action.SkipReason = "blocked by policy/config: marked dangerous; re-run with --confirm-dangerous to apply"
		}
	}

	if err := rep.Plan(ctx, actions); err != nil {
		return err
	}

	if planDryRun {
		fmt.Fprintln(cmd.OutOrStdout(), "\n[dry-run] Plan shown above.")
	}
	return nil
}
