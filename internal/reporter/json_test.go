package reporter_test

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/maestroi/hardener/internal/model"
	"github.com/maestroi/hardener/internal/reporter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJSONReporter_Audit(t *testing.T) {
	var buf bytes.Buffer
	r := reporter.NewJSONReporter(&buf)

	findings := []*model.Finding{
		{ID: "SSH-7408", Category: "SSH", Description: "PermitRootLogin not disabled", Severity: model.SeverityWarning, Source: "lynis"},
	}
	err := r.Audit(context.Background(), findings, 62)
	require.NoError(t, err)

	var out struct {
		Score    int              `json:"score"`
		Findings []*model.Finding `json:"findings"`
	}
	require.NoError(t, json.Unmarshal(buf.Bytes(), &out))
	assert.Equal(t, 62, out.Score)
	require.Len(t, out.Findings, 1)
	assert.Equal(t, "SSH-7408", out.Findings[0].ID)
}

func TestJSONReporter_Plan(t *testing.T) {
	var buf bytes.Buffer
	r := reporter.NewJSONReporter(&buf)

	actions := []*model.PlannedAction{
		{FindingID: "SSH-7408", ModuleID: "ssh-hardening", Applicable: true, Risk: model.RiskMedium},
		{FindingID: "KRNL-6000", ModuleID: "kernel-sysctl", Applicable: false, SkipReason: "validator profile"},
	}
	err := r.Plan(context.Background(), actions)
	require.NoError(t, err)

	var out struct {
		Actions []*model.PlannedAction `json:"actions"`
	}
	require.NoError(t, json.Unmarshal(buf.Bytes(), &out))
	require.Len(t, out.Actions, 2)
	assert.True(t, out.Actions[0].Applicable)
	assert.False(t, out.Actions[1].Applicable)
}

func TestJSONReporter_Score(t *testing.T) {
	var buf bytes.Buffer
	r := reporter.NewJSONReporter(&buf)
	require.NoError(t, r.Score(context.Background(), 62, 81, []string{"KRNL-6000"}))

	var out struct {
		Before  int      `json:"before"`
		After   int      `json:"after"`
		Delta   int      `json:"delta"`
		Skipped []string `json:"skipped"`
	}
	require.NoError(t, json.Unmarshal(buf.Bytes(), &out))
	assert.Equal(t, 62, out.Before)
	assert.Equal(t, 81, out.After)
	assert.Equal(t, 19, out.Delta)
}
