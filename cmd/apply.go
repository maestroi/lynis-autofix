package cmd

import "github.com/spf13/cobra"

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
	RunE: func(cmd *cobra.Command, args []string) error {
		cmd.Println("apply: not yet implemented")
		return nil
	},
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
