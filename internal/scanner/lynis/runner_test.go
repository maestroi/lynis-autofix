package lynis_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/maestroi/hardener/internal/scanner"
	"github.com/maestroi/hardener/internal/scanner/lynis"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRun_WritesReport(t *testing.T) {
	dir := t.TempDir()
	reportPath := filepath.Join(dir, "lynis-report.dat")
	logPath := filepath.Join(dir, "lynis.log")

	fakeLynis := filepath.Join(dir, "fake-lynis")
	script := "#!/bin/sh\n# Write a minimal report to --report-file\n" +
		"for arg; do\n  if [ \"$prev\" = \"--report-file\" ]; then\n" +
		"    echo 'hardening_index=55' > \"$arg\"\n" +
		"    echo 'suggestion[]=SSH-7408|Use strong ciphers||'\n" +
		"  fi\n  prev=$arg\ndone\nexit 0\n"
	require.NoError(t, os.WriteFile(fakeLynis, []byte(script), 0755))

	sc := lynis.New(fakeLynis, nil)
	err := sc.Run(context.Background(), scanner.ScanOptions{
		ReportPath: reportPath,
		LogPath:    logPath,
	})
	require.NoError(t, err)
	assert.FileExists(t, reportPath)
}

func TestRun_BinaryNotFound(t *testing.T) {
	sc := lynis.New("/nonexistent/lynis", nil)
	err := sc.Run(context.Background(), scanner.ScanOptions{
		ReportPath: "/tmp/test-report.dat",
	})
	assert.ErrorIs(t, err, lynis.ErrLynisNotFound)
}
