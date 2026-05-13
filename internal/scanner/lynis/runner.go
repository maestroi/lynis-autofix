package lynis

import (
	"context"
	"fmt"
	"os"

	"github.com/maestroi/hardener/internal/model"
	"github.com/maestroi/hardener/internal/scanner"
)

// LynisScanner implements scanner.Scanner using the lynis binary.
type LynisScanner struct {
	binaryPath string
	extraFlags []string
}

// New creates a LynisScanner.
func New(binaryPath string, extraFlags []string) *LynisScanner {
	return &LynisScanner{binaryPath: binaryPath, extraFlags: extraFlags}
}

// Run executes lynis audit system. (Full implementation in Milestone 2.)
func (s *LynisScanner) Run(_ context.Context, _ scanner.ScanOptions) error {
	return fmt.Errorf("lynis Run not implemented in Milestone 1")
}

// ParseReport reads and parses a lynis-report.dat file from disk.
func (s *LynisScanner) ParseReport(_ context.Context, path string) ([]*model.Finding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading report %s: %w", path, err)
	}
	return ParseReportBytes(data)
}

// Score reads the hardening_index from a lynis-report.dat file.
func (s *LynisScanner) Score(_ context.Context, path string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, fmt.Errorf("reading report %s: %w", path, err)
	}
	return ScoreFromBytes(data)
}
