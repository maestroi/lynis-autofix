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
