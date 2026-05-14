package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/maestroi/hardener/internal/model"
)

// complianceReport is the result of comparing a stored plan against the current Lynis scan.
type complianceReport struct {
	RunID         string   `json:"run_id"`
	StoredScore   int      `json:"stored_score"`
	CurrentScore  int      `json:"current_score"`
	Fixed         []string `json:"fixed"`      // finding IDs that were applicable, now absent
	StillOpen     []string `json:"still_open"` // finding IDs that were applicable, still present
	Skipped       []string `json:"skipped"`   // finding IDs that were not applicable in stored plan
	New           []string `json:"new"`       // finding IDs in current scan not in stored plan
	LiveAvailable bool     `json:"live_available"`
	LiveWarn      string   `json:"live_warn,omitempty"`
}

// compareFindings computes a complianceReport from the stored plan and the current scan findings.
func compareFindings(plan []*model.PlannedAction, current []*model.Finding) *complianceReport {
	currentIDs := make(map[string]bool, len(current))
	for _, f := range current {
		currentIDs[f.ID] = true
	}

	plannedIDs := make(map[string]bool, len(plan))
	for _, a := range plan {
		plannedIDs[a.FindingID] = true
	}

	report := &complianceReport{
		Fixed:     []string{},
		StillOpen: []string{},
		Skipped:   []string{},
		New:       []string{},
	}

	for _, a := range plan {
		if !a.Applicable {
			report.Skipped = append(report.Skipped, a.FindingID)
			continue
		}
		if currentIDs[a.FindingID] {
			report.StillOpen = append(report.StillOpen, a.FindingID)
		} else {
			report.Fixed = append(report.Fixed, a.FindingID)
		}
	}

	for _, f := range current {
		if !plannedIDs[f.ID] {
			report.New = append(report.New, f.ID)
		}
	}

	return report
}

// renderComplianceTable writes a human-readable compliance summary to w.
func renderComplianceTable(_ context.Context, w io.Writer, r *complianceReport) error {
	fmt.Fprintf(w, "\nCompliance report for run %s\n", r.RunID)
	if r.LiveWarn != "" {
		fmt.Fprintf(w, "[warn] %s\n", r.LiveWarn)
	}
	if r.LiveAvailable {
		fmt.Fprintf(w, "Score: %d → %d\n", r.StoredScore, r.CurrentScore)
	} else {
		fmt.Fprintf(w, "Score at run time: %d  (live score unavailable)\n", r.StoredScore)
	}
	fmt.Fprintln(w)

	printSection := func(label string, ids []string) {
		fmt.Fprintf(w, "  %-12s %d\n", label+":", len(ids))
		for _, id := range ids {
			fmt.Fprintf(w, "    - %s\n", id)
		}
	}

	printSection("Fixed", r.Fixed)
	printSection("Still open", r.StillOpen)
	printSection("Skipped", r.Skipped)
	printSection("New", r.New)
	return nil
}

// renderComplianceJSON writes a JSON compliance summary to w.
func renderComplianceJSON(_ context.Context, w io.Writer, r *complianceReport) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}
