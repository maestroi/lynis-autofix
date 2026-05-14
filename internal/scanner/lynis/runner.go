package lynis

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"time"

	"github.com/maestroi/hardener/internal/model"
	"github.com/maestroi/hardener/internal/scanner"
)

// ErrLynisNotFound is returned when the lynis binary cannot be found or executed.
var ErrLynisNotFound = errors.New("lynis binary not found")

// runTimeout is the maximum time allowed for a Lynis scan.
const runTimeout = 5 * time.Minute

// LynisScanner implements scanner.Scanner using the lynis binary.
type LynisScanner struct {
	binaryPath string
	extraFlags []string
}

// New creates a LynisScanner.
func New(binaryPath string, extraFlags []string) *LynisScanner {
	return &LynisScanner{binaryPath: binaryPath, extraFlags: extraFlags}
}

// Run executes lynis audit system and writes a report to opts.ReportPath.
// Returns ErrLynisNotFound if the binary does not exist or is not executable.
func (s *LynisScanner) Run(ctx context.Context, opts scanner.ScanOptions) error {
	if _, err := exec.LookPath(s.binaryPath); err != nil {
		if _, statErr := os.Stat(s.binaryPath); statErr != nil {
			return fmt.Errorf("%w: %s", ErrLynisNotFound, s.binaryPath)
		}
	}

	reportPath := opts.ReportPath
	if reportPath == "" {
		reportPath = "/var/log/lynis-report.dat"
	}

	args := []string{"audit", "system", "--report-file", reportPath, "--no-colors", "--quiet"}
	args = append(args, s.extraFlags...)

	ctx, cancel := context.WithTimeout(ctx, runTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, s.binaryPath, args...)

	var logW io.Writer = io.Discard
	if opts.LogPath != "" {
		f, err := os.OpenFile(opts.LogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0640)
		if err == nil {
			defer f.Close()
			logW = f
		}
	}
	cmd.Stdout = logW
	cmd.Stderr = logW

	if err := cmd.Run(); err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return fmt.Errorf("lynis timed out after %s", runTimeout)
		}
		return fmt.Errorf("lynis exited non-zero: %w", err)
	}
	return nil
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
