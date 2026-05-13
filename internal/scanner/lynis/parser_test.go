package lynis_test

import (
	"os"
	"testing"

	"github.com/maestroi/hardener/internal/model"
	"github.com/maestroi/hardener/internal/scanner/lynis"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseReportBytes_Warnings(t *testing.T) {
	data, err := os.ReadFile("../../../testdata/lynis-reports/basic.dat")
	require.NoError(t, err)

	findings, err := lynis.ParseReportBytes(data)
	require.NoError(t, err)

	var warnings []*model.Finding
	for _, f := range findings {
		if f.Severity == model.SeverityWarning {
			warnings = append(warnings, f)
		}
	}
	require.Len(t, warnings, 2)
	assert.Equal(t, "SSH-7408", warnings[0].ID)
	assert.Equal(t, "SSH", warnings[0].Category)
	assert.Equal(t, "sshd option PermitRootLogin is not disabled", warnings[0].Description)
	assert.Equal(t, model.SeverityWarning, warnings[0].Severity)
	assert.Equal(t, "lynis", warnings[0].Source)
}

func TestParseReportBytes_Suggestions(t *testing.T) {
	data, err := os.ReadFile("../../../testdata/lynis-reports/basic.dat")
	require.NoError(t, err)

	findings, err := lynis.ParseReportBytes(data)
	require.NoError(t, err)

	var suggestions []*model.Finding
	for _, f := range findings {
		if f.Severity == model.SeverityInfo {
			suggestions = append(suggestions, f)
		}
	}
	assert.Len(t, suggestions, 3)
	ids := make([]string, len(suggestions))
	for i, s := range suggestions {
		ids[i] = s.ID
	}
	assert.Contains(t, ids, "KRNL-6000")
	assert.Contains(t, ids, "FIRE-4513")
}

func TestParseReportBytes_DetailsInThirdField(t *testing.T) {
	data, err := os.ReadFile("../../../testdata/lynis-reports/basic.dat")
	require.NoError(t, err)

	findings, err := lynis.ParseReportBytes(data)
	require.NoError(t, err)

	var auth9262 *model.Finding
	for _, f := range findings {
		if f.ID == "AUTH-9262" {
			auth9262 = f
			break
		}
	}
	require.NotNil(t, auth9262)
	assert.Contains(t, auth9262.Details, "extra detail here")
}

func TestParseReportBytes_Empty(t *testing.T) {
	data, err := os.ReadFile("../../../testdata/lynis-reports/empty.dat")
	require.NoError(t, err)

	findings, err := lynis.ParseReportBytes(data)
	require.NoError(t, err)
	assert.Empty(t, findings)
}

func TestScoreFromBytes_BasicReport(t *testing.T) {
	data, err := os.ReadFile("../../../testdata/lynis-reports/basic.dat")
	require.NoError(t, err)

	score, err := lynis.ScoreFromBytes(data)
	require.NoError(t, err)
	assert.Equal(t, 62, score)
}

func TestScoreFromBytes_ScoreOnly(t *testing.T) {
	data, err := os.ReadFile("../../../testdata/lynis-reports/score-only.dat")
	require.NoError(t, err)

	score, err := lynis.ScoreFromBytes(data)
	require.NoError(t, err)
	assert.Equal(t, 81, score)
}

func TestScoreFromBytes_NoScore_ReturnsZero(t *testing.T) {
	score, err := lynis.ScoreFromBytes([]byte("warning[]=SSH-7408|desc|\n"))
	require.NoError(t, err)
	assert.Equal(t, 0, score)
}
