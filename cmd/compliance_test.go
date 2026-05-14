package cmd

import (
	"testing"

	"github.com/maestroi/hardener/internal/model"
	"github.com/stretchr/testify/assert"
)

func makeAction(findingID string, applicable bool) *model.PlannedAction {
	return &model.PlannedAction{
		FindingID:  findingID,
		ModuleID:   "test-module",
		Applicable: applicable,
	}
}

func makeFinding(id string) *model.Finding {
	return &model.Finding{ID: id, Category: model.CategoryFromID(id)}
}

func TestCompareFindings_Fixed(t *testing.T) {
	plan := []*model.PlannedAction{
		makeAction("SSH-7408", true),  // applicable — was targeted
		makeAction("AUTH-9262", true), // applicable — was targeted
	}
	// SSH-7408 is now absent from the current scan = fixed
	current := []*model.Finding{makeFinding("AUTH-9262")}

	report := compareFindings(plan, current)
	assert.Equal(t, []string{"SSH-7408"}, report.Fixed)
	assert.Equal(t, []string{"AUTH-9262"}, report.StillOpen)
	assert.Empty(t, report.Skipped)
	assert.Empty(t, report.New)
}

func TestCompareFindings_Skipped(t *testing.T) {
	plan := []*model.PlannedAction{
		makeAction("PKGS-7370", false), // not applicable — was skipped
	}
	current := []*model.Finding{}

	report := compareFindings(plan, current)
	assert.Empty(t, report.Fixed)
	assert.Empty(t, report.StillOpen)
	assert.Equal(t, []string{"PKGS-7370"}, report.Skipped)
	assert.Empty(t, report.New)
}

func TestCompareFindings_New(t *testing.T) {
	plan := []*model.PlannedAction{
		makeAction("SSH-7408", true),
	}
	// KRNL-6000 is in the current scan but was not in the stored plan at all
	current := []*model.Finding{
		makeFinding("SSH-7408"),
		makeFinding("KRNL-6000"),
	}

	report := compareFindings(plan, current)
	assert.Empty(t, report.Fixed)
	assert.Equal(t, []string{"SSH-7408"}, report.StillOpen)
	assert.Empty(t, report.Skipped)
	assert.Equal(t, []string{"KRNL-6000"}, report.New)
}

func TestCompareFindings_Mixed(t *testing.T) {
	plan := []*model.PlannedAction{
		makeAction("SSH-7408", true),   // fixed
		makeAction("AUTH-9262", true),  // still open
		makeAction("PKGS-7370", false), // skipped
	}
	current := []*model.Finding{
		makeFinding("AUTH-9262"), // still open
		makeFinding("LOGG-2154"), // new
	}

	report := compareFindings(plan, current)
	assert.Equal(t, []string{"SSH-7408"}, report.Fixed)
	assert.Equal(t, []string{"AUTH-9262"}, report.StillOpen)
	assert.Equal(t, []string{"PKGS-7370"}, report.Skipped)
	assert.Equal(t, []string{"LOGG-2154"}, report.New)
}
