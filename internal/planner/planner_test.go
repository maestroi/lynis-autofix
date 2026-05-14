package planner_test

import (
	"context"
	"testing"

	"github.com/maestroi/hardener/internal/executor"
	"github.com/maestroi/hardener/internal/model"
	"github.com/maestroi/hardener/internal/modules"
	"github.com/maestroi/hardener/internal/planner"
	"github.com/maestroi/hardener/internal/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type alwaysApplicableModule struct {
	id string
}

func (m *alwaysApplicableModule) Metadata() modules.ModuleMetadata {
	return modules.ModuleMetadata{ID: m.id, DefaultRisk: model.RiskLow}
}
func (m *alwaysApplicableModule) SupportedFindings() []string { return []string{"SSH-7408"} }
func (m *alwaysApplicableModule) Plan(_ context.Context, f *model.Finding, _ *model.Profile, _ executor.Inspector) (*model.PlannedAction, error) {
	return &model.PlannedAction{
		FindingID:   f.ID,
		ModuleID:    m.id,
		Title:       "Harden SSH",
		Applicable:  true,
		Risk:        model.RiskMedium,
		CanRollback: true,
	}, nil
}
func (m *alwaysApplicableModule) Apply(_ context.Context, _ *model.PlannedAction, _ executor.Executor) (*model.AppliedAction, error) {
	return nil, nil
}
func (m *alwaysApplicableModule) Validate(_ context.Context, _ *model.PlannedAction, _ executor.Inspector) error {
	return nil
}
func (m *alwaysApplicableModule) Rollback(_ context.Context, _ *model.RollbackEntry, _ executor.Executor) error {
	return nil
}

func TestPlanner_KnownFinding_ReturnsApplicableAction(t *testing.T) {
	reg := registry.New()
	reg.Register(&alwaysApplicableModule{id: "ssh-hardening"})

	p := planner.New(reg, executor.NewDryRunExecutor())
	profile := &model.Profile{MaxRiskLevel: model.RiskHigh, FailurePolicy: model.FailureRollbackAndStop}
	findings := []*model.Finding{{ID: "SSH-7408", Category: "SSH", Severity: model.SeverityWarning}}

	actions, err := p.Plan(context.Background(), findings, profile)
	require.NoError(t, err)
	require.Len(t, actions, 1)
	assert.True(t, actions[0].Applicable)
	assert.Equal(t, "SSH-7408", actions[0].FindingID)
}

func TestPlanner_UnknownFinding_MarksSkipped(t *testing.T) {
	reg := registry.New()
	p := planner.New(reg, executor.NewDryRunExecutor())
	profile := &model.Profile{MaxRiskLevel: model.RiskHigh}
	findings := []*model.Finding{{ID: "UNKN-9999", Category: "UNKN"}}

	actions, err := p.Plan(context.Background(), findings, profile)
	require.NoError(t, err)
	require.Len(t, actions, 1)
	assert.False(t, actions[0].Applicable)
	assert.Contains(t, actions[0].SkipReason, "no module")
}

func TestPlanner_DeduplicatesFindingIDs(t *testing.T) {
	reg := registry.New()
	reg.Register(&alwaysApplicableModule{id: "ssh-hardening"})

	p := planner.New(reg, executor.NewDryRunExecutor())
	profile := &model.Profile{MaxRiskLevel: model.RiskHigh}
	findings := []*model.Finding{
		{ID: "SSH-7408", Category: "SSH"},
		{ID: "SSH-7408", Category: "SSH"},
	}

	actions, err := p.Plan(context.Background(), findings, profile)
	require.NoError(t, err)
	require.Len(t, actions, 1)
	assert.Equal(t, "SSH-7408", actions[0].FindingID)
}
