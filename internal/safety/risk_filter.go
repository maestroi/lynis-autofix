package safety

import (
	"context"
	"fmt"

	"github.com/maestroi/hardener/internal/executor"
	"github.com/maestroi/hardener/internal/model"
)

// RiskFilter skips actions whose risk level exceeds the profile's MaxRiskLevel.
type RiskFilter struct {
	profile *model.Profile
}

// NewRiskFilter creates a RiskFilter for the given profile.
func NewRiskFilter(profile *model.Profile) *RiskFilter {
	return &RiskFilter{profile: profile}
}

func (f *RiskFilter) Check(_ context.Context, action *model.PlannedAction, _ executor.Executor) (*SafetyResult, error) {
	if action.Risk > f.profile.MaxRiskLevel {
		return &SafetyResult{
			Safe: false,
			Reason: fmt.Sprintf("blocked by policy/config: risk level %q exceeds profile maximum %q",
				action.Risk.String(), f.profile.MaxRiskLevel.String()),
		}, nil
	}
	return &SafetyResult{Safe: true}, nil
}
