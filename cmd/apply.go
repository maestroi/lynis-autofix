package cmd

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/maestroi/hardener/internal/backup"
	"github.com/maestroi/hardener/internal/config"
	"github.com/maestroi/hardener/internal/executor"
	"github.com/maestroi/hardener/internal/model"
	"github.com/maestroi/hardener/internal/planner"
	"github.com/maestroi/hardener/internal/registry"
	"github.com/maestroi/hardener/internal/reporter"
	"github.com/maestroi/hardener/internal/safety"
	"github.com/maestroi/hardener/internal/scanner/lynis"
	"github.com/maestroi/hardener/internal/state"
)

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
	RunE:  runApply,
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

func runApply(cmd *cobra.Command, args []string) error {
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

	profile, err := config.LoadBundledProfile(cfg.Profile)
	if err != nil {
		return fmt.Errorf("loading profile %q: %w", cfg.Profile, err)
	}

	localInspect := executor.NewLocalExecutor()
	var mutExec executor.Executor
	if applyDryRun {
		mutExec = executor.NewDryRunExecutor()
		fmt.Fprintln(cmd.OutOrStdout(), "[dry-run] No changes will be made to this system.")
	} else {
		mutExec = localInspect
	}

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
	scoreBefore, _ := sc.Score(ctx, cfg.Lynis.ReportPath)

	reg := registry.Default()
	findings = filterFindings(findings, reg, applyFindings, applyModules)

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

	confirmDangerous := applyConfirmDangerous || cfg.ConfirmDangerous
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

	if applyDryRun {
		fmt.Fprintln(cmd.OutOrStdout(), "\n[dry-run] Plan shown above. No changes applied.")
		return nil
	}

	var toApply []*model.PlannedAction
	for _, a := range actions {
		if a.Applicable {
			toApply = append(toApply, a)
		}
	}
	if len(toApply) == 0 {
		fmt.Fprintln(cmd.OutOrStdout(), "\nNo applicable actions to apply.")
		return nil
	}

	if !applyYes {
		fmt.Fprintf(cmd.OutOrStdout(), "\nApply %d action(s)? [y/N] ", len(toApply))
		sc := bufio.NewScanner(cmd.InOrStdin())
		if !sc.Scan() {
			return fmt.Errorf("reading confirmation")
		}
		answer := strings.TrimSpace(sc.Text())
		if answer != "y" && answer != "Y" {
			fmt.Fprintln(cmd.OutOrStdout(), "Apply cancelled.")
			return nil
		}
	}

	store, err := state.NewFileStore(cfg.StateDir)
	if err != nil {
		return fmt.Errorf("opening state store: %w", err)
	}

	run, err := store.InitRun(ctx, profile.Name, false)
	if err != nil {
		return fmt.Errorf("starting run: %w", err)
	}
	if err := store.SavePlan(ctx, run.ID, actions); err != nil {
		return fmt.Errorf("saving plan: %w", err)
	}

	bs := backup.NewStore(filepath.Join(cfg.StateDir, "backups"))
	var applied []*model.AppliedAction
	rollbackIdx := 0

	for _, action := range actions {
		if !action.Applicable {
			continue
		}
		mod, ok := reg.Lookup(action.FindingID)
		if !ok {
			continue
		}

		targetPath := ""
		if action.Metadata != nil {
			targetPath = action.Metadata["target_file"]
		}
		if action.CanRollback && targetPath != "" {
			entry, snapErr := bs.SnapshotFile(ctx, run.ID, action.ModuleID, action.FindingID, rollbackIdx, targetPath)
			if snapErr != nil {
				return fmt.Errorf("snapshot %s before %s: %w", targetPath, action.FindingID, snapErr)
			}
			if err := store.AppendRollbackEntry(ctx, run.ID, entry); err != nil {
				return fmt.Errorf("recording rollback entry: %w", err)
			}
			rollbackIdx++
		}

		appliedAction, applyErr := mod.Apply(ctx, action, mutExec)
		if applyErr != nil {
			return fmt.Errorf("apply %s: %w", action.FindingID, applyErr)
		}
		if valErr := mod.Validate(ctx, action, localInspect); valErr != nil {
			return fmt.Errorf("validate %s: %w", action.FindingID, valErr)
		}
		if err := store.RecordApplied(ctx, run.ID, appliedAction); err != nil {
			return fmt.Errorf("recording applied action: %w", err)
		}
		applied = append(applied, appliedAction)
	}

	if err := store.CompleteRun(ctx, run.ID, model.RunCompleted); err != nil {
		return fmt.Errorf("completing run: %w", err)
	}

	run, err = store.GetRun(ctx, run.ID)
	if err != nil {
		return err
	}

	if err := rep.Applied(ctx, run, applied); err != nil {
		return err
	}
	return rep.Score(ctx, scoreBefore, scoreBefore, nil)
}
