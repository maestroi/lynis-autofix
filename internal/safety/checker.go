package safety

import (
	"context"

	"github.com/maestroi/hardener/internal/executor"
	"github.com/maestroi/hardener/internal/model"
)

// SafetyResult is the outcome of a single safety check.
type SafetyResult struct {
	Safe    bool
	Reason  string
	Warning string
}

// Checker evaluates one safety concern for a planned action.
type Checker interface {
	Check(ctx context.Context, action *model.PlannedAction, exec executor.Executor) (*SafetyResult, error)
}

// RunAll runs all checkers against an action. Returns the first failing result,
// or a passing result with any accumulated warnings.
func RunAll(ctx context.Context, checkers []Checker, action *model.PlannedAction, exec executor.Executor) (*SafetyResult, error) {
	combined := &SafetyResult{Safe: true}
	for _, c := range checkers {
		result, err := c.Check(ctx, action, exec)
		if err != nil {
			return nil, err
		}
		if !result.Safe {
			return result, nil
		}
		if result.Warning != "" {
			if combined.Warning != "" {
				combined.Warning += "; "
			}
			combined.Warning += result.Warning
		}
	}
	return combined, nil
}
