package safety

import (
	"context"
	"fmt"

	"github.com/maestroi/hardener/internal/executor"
	"github.com/maestroi/hardener/internal/model"
)

// ProfileFilter enforces scope-aware protected resource rules from a Profile.
type ProfileFilter struct {
	profile *model.Profile
}

// NewProfileFilter creates a ProfileFilter for the given profile.
func NewProfileFilter(profile *model.Profile) *ProfileFilter {
	return &ProfileFilter{profile: profile}
}

func (f *ProfileFilter) Check(_ context.Context, action *model.PlannedAction, _ executor.Executor) (*SafetyResult, error) {
	if f.profile.IsModuleBlocked(action.ModuleID) {
		return &SafetyResult{
			Safe:   false,
			Reason: fmt.Sprintf("module %q blocked by profile %q", action.ModuleID, f.profile.Name),
		}, nil
	}
	if !f.profile.IsModuleAllowed(action.ModuleID) {
		return &SafetyResult{
			Safe:   false,
			Reason: fmt.Sprintf("module %q not in allowed_modules list for profile %q", action.ModuleID, f.profile.Name),
		}, nil
	}

	if hasTag(action.Tags, "service-restart", "service-disable") {
		if svc, ok := metaGet(action.Metadata, "service_name"); ok {
			if f.profile.IsServiceProtected(svc) {
				return &SafetyResult{
					Safe:   false,
					Reason: fmt.Sprintf("protected service %q cannot be restarted/disabled per profile", svc),
				}, nil
			}
		}
	}

	if hasTag(action.Tags, "process-restart", "process-kill") {
		if proc, ok := metaGet(action.Metadata, "process_name"); ok {
			if f.profile.IsProcessProtected(proc) {
				return &SafetyResult{
					Safe:   false,
					Reason: fmt.Sprintf("protected process %q cannot be affected per profile", proc),
				}, nil
			}
		}
	}

	return &SafetyResult{Safe: true}, nil
}

func metaGet(m map[string]string, key string) (string, bool) {
	if m == nil {
		return "", false
	}
	v, ok := m[key]
	return v, ok
}

func hasTag(tags []string, targets ...string) bool {
	for _, t := range tags {
		for _, target := range targets {
			if t == target {
				return true
			}
		}
	}
	return false
}
