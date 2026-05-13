package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	flagStateDir string
	flagProfile  string
	flagOutput   string
	flagConfig   string
	flagVerbose  bool
)

var rootCmd = &cobra.Command{
	Use:   "hardener",
	Short: "Linux hardening automation tool",
	Long:  "A safe, idempotent, rollback-capable Linux hardening tool powered by Lynis findings.",
}

// Execute runs the root command. Called from main().
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVar(&flagStateDir, "state-dir", "/var/lib/hardener", "state directory")
	rootCmd.PersistentFlags().StringVar(&flagProfile, "profile", "server", "profile name or path to yaml file")
	rootCmd.PersistentFlags().StringVar(&flagOutput, "output", "table", "output format: table|json")
	rootCmd.PersistentFlags().StringVar(&flagConfig, "config", "", "path to hardener.yaml")
	rootCmd.PersistentFlags().BoolVar(&flagVerbose, "verbose", false, "verbose output")
}
