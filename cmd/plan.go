package cmd

import "github.com/spf13/cobra"

var (
	planFresh    bool
	planFindings []string
	planModules  []string
)

var planCmd = &cobra.Command{
	Use:   "plan",
	Short: "Show remediation plan without applying anything",
	RunE: func(cmd *cobra.Command, args []string) error {
		cmd.Println("plan: not yet implemented")
		return nil
	},
}

func init() {
	planCmd.Flags().BoolVar(&planFresh, "fresh", false, "run Lynis scan before planning")
	planCmd.Flags().StringSliceVar(&planFindings, "finding", nil, "limit to finding IDs")
	planCmd.Flags().StringSliceVar(&planModules, "module", nil, "limit to module IDs")
	rootCmd.AddCommand(planCmd)
}
