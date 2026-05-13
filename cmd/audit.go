package cmd

import "github.com/spf13/cobra"

var auditFresh bool
var auditReportPath string

var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Run Lynis and display findings + current hardening score",
	RunE: func(cmd *cobra.Command, args []string) error {
		cmd.Println("audit: not yet implemented")
		return nil
	},
}

func init() {
	auditCmd.Flags().BoolVar(&auditFresh, "fresh", false, "force a new Lynis scan")
	auditCmd.Flags().StringVar(&auditReportPath, "report-path", "", "parse a specific report file")
	rootCmd.AddCommand(auditCmd)
}
