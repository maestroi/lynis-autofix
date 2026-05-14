package cmd

import (
	"bufio"
	"context"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/maestroi/hardener/internal/executor"
	"github.com/maestroi/hardener/internal/model"
	"github.com/maestroi/hardener/internal/registry"
	"github.com/maestroi/hardener/internal/reporter"
	"github.com/maestroi/hardener/internal/rollback"
	"github.com/maestroi/hardener/internal/state"
)

var (
	rollbackRunID  string
	rollbackDryRun bool
	rollbackYes    bool
	rollbackList   bool
)

var rollbackCmd = &cobra.Command{
	Use:   "rollback",
	Short: "Reverse a previous run",
	RunE:  runRollback,
}

func init() {
	rollbackCmd.Flags().StringVar(&rollbackRunID, "run-id", "", "run ID to roll back")
	rollbackCmd.Flags().BoolVar(&rollbackDryRun, "dry-run", false, "preview rollback without executing")
	rollbackCmd.Flags().BoolVar(&rollbackYes, "yes", false, "skip confirmation prompt")
	rollbackCmd.Flags().BoolVar(&rollbackList, "list", false, "list runs with rollback manifests")
	rootCmd.AddCommand(rollbackCmd)
}

func runRollback(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	store, err := state.NewFileStore(flagStateDir)
	if err != nil {
		return fmt.Errorf("opening state store: %w", err)
	}

	var rep reporter.Reporter
	switch flagOutput {
	case "json":
		rep = reporter.NewJSONReporter(cmd.OutOrStdout())
	default:
		rep = reporter.NewTerminalReporter(cmd.OutOrStdout())
	}

	if rollbackList {
		runs, err := store.ListRuns(ctx)
		if err != nil {
			return err
		}
		return rep.History(ctx, runs)
	}

	if rollbackRunID == "" {
		return fmt.Errorf("--run-id is required (use --list to see available runs)")
	}

	manifest, err := store.LoadRollbackManifest(ctx, rollbackRunID)
	if err != nil {
		return fmt.Errorf("loading rollback manifest: %w", err)
	}

	if err := rep.RollbackPreview(ctx, manifest); err != nil {
		return err
	}

	if rollbackDryRun {
		fmt.Fprintln(cmd.OutOrStdout(), "[dry-run] Rollback preview shown. No changes made.")
		return nil
	}

	if !rollbackYes {
		fmt.Fprintf(cmd.OutOrStdout(), "\nProceed with rollback of run %s? [y/N] ", rollbackRunID)
		sc := bufio.NewScanner(cmd.InOrStdin())
		if !sc.Scan() {
			return fmt.Errorf("reading confirmation")
		}
		answer := strings.TrimSpace(sc.Text())
		if answer != "y" && answer != "Y" {
			fmt.Fprintln(cmd.OutOrStdout(), "Rollback cancelled.")
			return nil
		}
	}

	mutExec := executor.NewLocalExecutor()
	reg := registry.Default()
	mgr := rollback.NewManager(reg)

	if err := mgr.Rollback(ctx, manifest, mutExec); err != nil {
		return fmt.Errorf("rollback failed: %w", err)
	}

	if err := store.CompleteRun(ctx, rollbackRunID, model.RunRolledBack); err != nil {
		return fmt.Errorf("recording rollback status: %w", err)
	}

	fmt.Fprintf(cmd.OutOrStdout(), "\nRollback of run %s complete.\n", rollbackRunID)
	return nil
}
