package cmd

import "github.com/spf13/cobra"

var reportRunID string

var reportCmd = &cobra.Command{
	Use:   "report",
	Short: "Show run history and before/after scores",
	RunE: func(cmd *cobra.Command, args []string) error {
		cmd.Println("report: not yet implemented")
		return nil
	},
}

func init() {
	reportCmd.Flags().StringVar(&reportRunID, "run-id", "", "drill into a single run")
	rootCmd.AddCommand(reportCmd)
}
