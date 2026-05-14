package model_test

import (
	"encoding/json"
	"testing"

	"github.com/maestroi/hardener/internal/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestRiskLevel_String(t *testing.T) {
	assert.Equal(t, "none", model.RiskNone.String())
	assert.Equal(t, "low", model.RiskLow.String())
	assert.Equal(t, "medium", model.RiskMedium.String())
	assert.Equal(t, "high", model.RiskHigh.String())
	assert.Equal(t, "critical", model.RiskCritical.String())
}

func TestRiskLevel_MarshalJSON(t *testing.T) {
	type wrapper struct {
		Risk model.RiskLevel `json:"risk"`
	}
	b, err := json.Marshal(wrapper{Risk: model.RiskHigh})
	require.NoError(t, err)
	assert.JSONEq(t, `{"risk":"high"}`, string(b))
}

func TestRiskLevel_UnmarshalYAML(t *testing.T) {
	type wrapper struct {
		Risk model.RiskLevel `yaml:"risk"`
	}
	tests := []struct {
		input string
		want  model.RiskLevel
	}{
		{"risk: none\n", model.RiskNone},
		{"risk: low\n", model.RiskLow},
		{"risk: medium\n", model.RiskMedium},
		{"risk: high\n", model.RiskHigh},
		{"risk: critical\n", model.RiskCritical},
		{"risk: HIGH\n", model.RiskHigh}, // case-insensitive
	}
	for _, tt := range tests {
		var w wrapper
		err := yaml.Unmarshal([]byte(tt.input), &w)
		require.NoError(t, err, "input: %q", tt.input)
		assert.Equal(t, tt.want, w.Risk, "input: %q", tt.input)
	}
}

func TestRiskLevel_UnmarshalYAML_InvalidValue(t *testing.T) {
	type wrapper struct {
		Risk model.RiskLevel `yaml:"risk"`
	}
	var w wrapper
	err := yaml.Unmarshal([]byte("risk: extreme\n"), &w)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "extreme")
}

func TestPlannedAction_Defaults(t *testing.T) {
	a := model.PlannedAction{
		FindingID:  "SSH-7408",
		ModuleID:   "ssh-hardening",
		Applicable: true,
	}
	assert.False(t, a.Dangerous)
	assert.False(t, a.RequiresReboot)
	assert.True(t, a.Applicable)
}
