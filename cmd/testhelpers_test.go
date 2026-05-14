package cmd

import (
	"io"
	"os"
	"testing"

	"github.com/spf13/cobra"
)

func newTestRoot(w io.Writer) *cobra.Command {
	root := &cobra.Command{Use: "hardener"}
	root.PersistentFlags().StringVar(&flagStateDir, "state-dir", "/var/lib/hardener", "")
	root.PersistentFlags().StringVar(&flagProfile, "profile", "server", "")
	root.PersistentFlags().StringVar(&flagOutput, "output", "table", "")
	root.PersistentFlags().StringVar(&flagConfig, "config", "", "")
	root.PersistentFlags().BoolVar(&flagVerbose, "verbose", false, "")
	root.SetOut(w)
	root.AddCommand(newAuditCmd(w))
	root.AddCommand(newReportCmd(w))
	return root
}

func writeFile(t *testing.T, path, content string) error {
	t.Helper()
	return os.WriteFile(path, []byte(content), 0644)
}
