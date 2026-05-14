package manual_test

import (
	"context"
	"testing"

	"github.com/maestroi/hardener/internal/model"
	manualmod "github.com/maestroi/hardener/internal/modules/advisory/manual"
	"github.com/maestroi/hardener/internal/testhelpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestManual_Metadata(t *testing.T) {
	m := manualmod.New()
	meta := m.Metadata()
	assert.Equal(t, "advisory-manual", meta.ID)
	assert.Equal(t, model.RiskNone, meta.DefaultRisk)
	assert.False(t, meta.CanRollback)
}

func TestManual_SupportedFindings(t *testing.T) {
	findings := manualmod.New().SupportedFindings()
	assert.Empty(t, findings)
}

func TestManual_Plan_NotApplicableWithReason(t *testing.T) {
	m := manualmod.New()
	action, err := m.Plan(
		context.Background(),
		&model.Finding{ID: "BOOT-5122"},
		&model.Profile{},
		&testhelpers.FakeInspector{},
	)
	require.NoError(t, err)
	assert.False(t, action.Applicable)
	assert.Equal(t, "advisory-manual", action.ModuleID)
	assert.Contains(t, action.SkipReason, "manual")
}

func TestManual_Apply_ReturnsSkipped(t *testing.T) {
	m := manualmod.New()
	applied, err := m.Apply(
		context.Background(),
		&model.PlannedAction{FindingID: "BOOT-5122", ModuleID: "advisory-manual"},
		&testhelpers.FakeExecutor{},
	)
	require.NoError(t, err)
	assert.Equal(t, model.ActionSkipped, applied.Status)
}
