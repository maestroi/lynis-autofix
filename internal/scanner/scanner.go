package scanner

import (
	"context"

	"github.com/maestroi/hardener/internal/model"
)

// ScanOptions configures a Lynis scan run.
type ScanOptions struct {
	ReportPath string
	LogPath    string
	ExtraFlags []string
}

// Scanner produces Findings from an audit tool.
type Scanner interface {
	Run(ctx context.Context, opts ScanOptions) error
	ParseReport(ctx context.Context, path string) ([]*model.Finding, error)
	Score(ctx context.Context, path string) (int, error)
}
