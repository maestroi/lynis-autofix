package reporter

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/fatih/color"
	"github.com/olekukonko/tablewriter"

	"github.com/maestroi/hardener/internal/model"
)

// TerminalReporter renders human-readable colored output to a writer.
type TerminalReporter struct {
	w       io.Writer
	useColor bool
}

// NewTerminalReporter creates a TerminalReporter. Pass os.Stdout for production use.
func NewTerminalReporter(w io.Writer) *TerminalReporter {
	return &TerminalReporter{w: w, useColor: w == os.Stdout}
}

func (r *TerminalReporter) colorWarning() *color.Color {
	c := color.New(color.FgYellow, color.Bold)
	if !r.useColor {
		c.DisableColor()
	}
	return c
}

func (r *TerminalReporter) colorCritical() *color.Color {
	c := color.New(color.FgRed, color.Bold)
	if !r.useColor {
		c.DisableColor()
	}
	return c
}

func (r *TerminalReporter) colorSkipped() *color.Color {
	c := color.New(color.FgHiBlack)
	if !r.useColor {
		c.DisableColor()
	}
	return c
}

func (r *TerminalReporter) colorScore() *color.Color {
	c := color.New(color.FgCyan, color.Bold)
	if !r.useColor {
		c.DisableColor()
	}
	return c
}

func (r *TerminalReporter) Audit(_ context.Context, findings []*model.Finding, score int) error {
	fmt.Fprintf(r.w, "\nHardening score: %s\n\n", r.colorScore().Sprintf("%d", score))

	tbl := tablewriter.NewWriter(r.w)
	tbl.SetHeader([]string{"ID", "Category", "Severity", "Description"})
	tbl.SetBorder(false)
	tbl.SetColumnSeparator("  ")
	tbl.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
	tbl.SetAlignment(tablewriter.ALIGN_LEFT)
	tbl.SetAutoWrapText(true)
	tbl.SetColWidth(60)

	for _, f := range findings {
		sev := r.severityLabel(f.Severity)
		desc := truncate(f.Description, 60)
		tbl.Append([]string{f.ID, f.Category, sev, desc})
	}
	tbl.Render()
	fmt.Fprintf(r.w, "\n%d finding(s)\n", len(findings))
	return nil
}

func (r *TerminalReporter) Plan(_ context.Context, actions []*model.PlannedAction) error {
	applicable := make([]*model.PlannedAction, 0)
	skipped := make([]*model.PlannedAction, 0)
	for _, a := range actions {
		if a.Applicable {
			applicable = append(applicable, a)
		} else {
			skipped = append(skipped, a)
		}
	}

	fmt.Fprintf(r.w, "\nRemediation plan — %d applicable, %d skipped\n\n", len(applicable), len(skipped))

	if len(applicable) > 0 {
		tbl := tablewriter.NewWriter(r.w)
		tbl.SetHeader([]string{"Finding", "Module", "Risk", "Impact", "Rollback", "Reboot"})
		tbl.SetBorder(false)
		tbl.SetColumnSeparator("  ")
		tbl.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
		tbl.SetAlignment(tablewriter.ALIGN_LEFT)
		for _, a := range applicable {
			rb := "yes"
			if !a.CanRollback {
				rb = "no"
			}
			reboot := "-"
			if a.RequiresReboot {
				reboot = "YES"
			}
			tbl.Append([]string{a.FindingID, a.ModuleID, a.Risk.String(), truncate(a.Impact, 40), rb, reboot})
		}
		tbl.Render()
	}

	if len(skipped) > 0 {
		fmt.Fprintf(r.w, "\nSkipped:\n")
		for _, a := range skipped {
			fmt.Fprintf(r.w, "  %s  %s\n", r.colorSkipped().Sprint(a.FindingID), a.SkipReason)
		}
	}
	return nil
}

func (r *TerminalReporter) Applied(_ context.Context, run *model.Run, actions []*model.AppliedAction) error {
	fmt.Fprintf(r.w, "\nRun: %s  Status: %s\n\n", run.ID, string(run.Status))

	tbl := tablewriter.NewWriter(r.w)
	tbl.SetHeader([]string{"Finding", "Module", "Status", "Error"})
	tbl.SetBorder(false)
	tbl.SetColumnSeparator("  ")
	tbl.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
	tbl.SetAlignment(tablewriter.ALIGN_LEFT)
	for _, a := range actions {
		errMsg := truncate(a.Error, 40)
		tbl.Append([]string{a.FindingID, a.ModuleID, string(a.Status), errMsg})
	}
	tbl.Render()
	return nil
}

func (r *TerminalReporter) Score(_ context.Context, before, after int, skipped []string) error {
	delta := after - before
	sign := "+"
	if delta < 0 {
		sign = ""
	}
	fmt.Fprintf(r.w, "\nHardening score:  %d  →  %s  (%s%d)\n",
		before,
		r.colorScore().Sprintf("%d", after),
		sign, delta,
	)
	if len(skipped) > 0 {
		fmt.Fprintf(r.w, "Skipped findings: %s\n", strings.Join(skipped, ", "))
	}
	return nil
}

func (r *TerminalReporter) RollbackPreview(_ context.Context, manifest *model.RollbackManifest) error {
	fmt.Fprintf(r.w, "\nRollback preview for run %s — %d entries\n\n", manifest.RunID, len(manifest.Entries))
	for _, e := range manifest.Entries {
		fmt.Fprintf(r.w, "  [%d] %s  %s\n", e.Index, string(e.Kind), e.Description)
	}
	return nil
}

func (r *TerminalReporter) History(_ context.Context, runs []*model.Run) error {
	if len(runs) == 0 {
		fmt.Fprintln(r.w, "No runs found.")
		return nil
	}
	tbl := tablewriter.NewWriter(r.w)
	tbl.SetHeader([]string{"Run ID", "Started", "Status", "Profile", "Before", "After"})
	tbl.SetBorder(false)
	tbl.SetColumnSeparator("  ")
	tbl.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
	tbl.SetAlignment(tablewriter.ALIGN_LEFT)
	for _, run := range runs {
		tbl.Append([]string{
			run.ID,
			run.StartedAt.Format("2006-01-02 15:04"),
			string(run.Status),
			run.ProfileName,
			fmt.Sprintf("%d", run.ScoreBefore),
			fmt.Sprintf("%d", run.ScoreAfter),
		})
	}
	tbl.Render()
	return nil
}

func (r *TerminalReporter) severityLabel(s model.Severity) string {
	switch s {
	case model.SeverityWarning:
		return r.colorWarning().Sprint("WARNING")
	case model.SeverityCritical:
		return r.colorCritical().Sprint("CRITICAL")
	default:
		return "INFO"
	}
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-1] + "…"
}
