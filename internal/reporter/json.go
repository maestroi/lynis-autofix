package reporter

import (
	"context"
	"encoding/json"
	"io"

	"github.com/maestroi/hardener/internal/model"
)

// JSONReporter serializes output as JSON. All methods write a single JSON object per call.
type JSONReporter struct {
	w io.Writer
}

// NewJSONReporter creates a JSONReporter writing to w.
func NewJSONReporter(w io.Writer) *JSONReporter {
	return &JSONReporter{w: w}
}

func (r *JSONReporter) encode(v interface{}) error {
	enc := json.NewEncoder(r.w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func (r *JSONReporter) Audit(_ context.Context, findings []*model.Finding, score int) error {
	return r.encode(map[string]interface{}{
		"score":    score,
		"findings": findings,
	})
}

func (r *JSONReporter) Plan(_ context.Context, actions []*model.PlannedAction) error {
	return r.encode(map[string]interface{}{"actions": actions})
}

func (r *JSONReporter) Applied(_ context.Context, run *model.Run, actions []*model.AppliedAction) error {
	return r.encode(map[string]interface{}{
		"run":     run,
		"actions": actions,
	})
}

func (r *JSONReporter) Score(_ context.Context, before, after int, skipped []string) error {
	return r.encode(map[string]interface{}{
		"before":  before,
		"after":   after,
		"delta":   after - before,
		"skipped": skipped,
	})
}

func (r *JSONReporter) RollbackPreview(_ context.Context, manifest *model.RollbackManifest) error {
	return r.encode(manifest)
}

func (r *JSONReporter) History(_ context.Context, runs []*model.Run) error {
	return r.encode(map[string]interface{}{"runs": runs})
}
