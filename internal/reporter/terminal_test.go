package reporter_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/maestroi/hardener/internal/model"
	"github.com/maestroi/hardener/internal/reporter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTerminalReporter_Audit_ContainsFindings(t *testing.T) {
	var buf bytes.Buffer
	r := reporter.NewTerminalReporter(&buf)

	findings := []*model.Finding{
		{ID: "SSH-7408", Category: "SSH", Description: "PermitRootLogin not disabled", Severity: model.SeverityWarning},
		{ID: "KRNL-6000", Category: "KRNL", Description: "Sysctl values differ", Severity: model.SeverityInfo},
	}
	err := r.Audit(context.Background(), findings, 62)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "SSH-7408")
	assert.Contains(t, output, "KRNL-6000")
	assert.Contains(t, output, "62")
}

func TestTerminalReporter_Plan_ShowsApplicableAndSkipped(t *testing.T) {
	var buf bytes.Buffer
	r := reporter.NewTerminalReporter(&buf)

	actions := []*model.PlannedAction{
		{FindingID: "SSH-7408", ModuleID: "ssh-hardening", Title: "Harden SSH", Applicable: true, Risk: model.RiskMedium, CanRollback: true},
		{FindingID: "KRNL-6000", ModuleID: "kernel-sysctl", Title: "Tune sysctl", Applicable: false, SkipReason: "validator profile blocks kernel changes"},
	}
	err := r.Plan(context.Background(), actions)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "SSH-7408")
	assert.Contains(t, output, "KRNL-6000")
	assert.Contains(t, output, "validator profile blocks kernel changes")
}

func TestTerminalReporter_Score_ShowsDelta(t *testing.T) {
	var buf bytes.Buffer
	r := reporter.NewTerminalReporter(&buf)
	require.NoError(t, r.Score(context.Background(), 62, 81, nil))

	output := buf.String()
	assert.Contains(t, output, "62")
	assert.Contains(t, output, "81")
	assert.Contains(t, output, "+19")
}
