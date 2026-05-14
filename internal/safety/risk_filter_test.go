package safety_test

import (
	"context"
	"testing"

	"github.com/maestroi/hardener/internal/executor"
	"github.com/maestroi/hardener/internal/model"
	"github.com/maestroi/hardener/internal/safety"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRiskFilter_AboveThreshold_NotSafe(t *testing.T) {
	profile := &model.Profile{MaxRiskLevel: model.RiskMedium}
	filter := safety.NewRiskFilter(profile)

	action := &model.PlannedAction{Risk: model.RiskHigh}
	result, err := filter.Check(context.Background(), action, executor.NewDryRunExecutor())
	require.NoError(t, err)
	assert.False(t, result.Safe)
	assert.Contains(t, result.Reason, "risk level")
}

func TestRiskFilter_AtThreshold_Safe(t *testing.T) {
	profile := &model.Profile{MaxRiskLevel: model.RiskMedium}
	filter := safety.NewRiskFilter(profile)

	action := &model.PlannedAction{Risk: model.RiskMedium}
	result, err := filter.Check(context.Background(), action, executor.NewDryRunExecutor())
	require.NoError(t, err)
	assert.True(t, result.Safe)
}

func TestRiskFilter_BelowThreshold_Safe(t *testing.T) {
	profile := &model.Profile{MaxRiskLevel: model.RiskHigh}
	filter := safety.NewRiskFilter(profile)

	action := &model.PlannedAction{Risk: model.RiskLow}
	result, err := filter.Check(context.Background(), action, executor.NewDryRunExecutor())
	require.NoError(t, err)
	assert.True(t, result.Safe)
}
