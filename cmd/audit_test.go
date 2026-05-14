package cmd

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fixtureReport is a minimal lynis-report.dat content for testing.
const fixtureReport = `
hardening_index=62
suggestion[]=SSH-7408|Enable strong ciphers||
warning[]=AUTH-9262|Set password quality requirements||
`

func runAuditCmd(t *testing.T, args []string, reportContent string) (string, error) {
	t.Helper()
	dir := t.TempDir()
	reportPath := filepath.Join(dir, "lynis-report.dat")
	require.NoError(t, writeFile(t, reportPath, reportContent))

	buf := &bytes.Buffer{}
	cmd := newTestRoot(buf)
	cmd.SetArgs(append([]string{"audit", "--report-path", reportPath, "--state-dir", dir}, args...))
	err := cmd.Execute()
	return buf.String(), err
}

func TestAuditCmd_ParsesReport(t *testing.T) {
	out, err := runAuditCmd(t, nil, fixtureReport)
	require.NoError(t, err)
	assert.Contains(t, out, "SSH-7408")
	assert.Contains(t, out, "62")
}

func TestAuditCmd_JSONOutput(t *testing.T) {
	out, err := runAuditCmd(t, []string{"--output", "json"}, fixtureReport)
	require.NoError(t, err)
	assert.Contains(t, out, `"score"`)
	assert.Contains(t, out, `"SSH-7408"`)
}
