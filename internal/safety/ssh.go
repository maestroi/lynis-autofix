package safety

import (
	"context"
	"fmt"
	"strings"

	"github.com/maestroi/hardener/internal/executor"
	"github.com/maestroi/hardener/internal/model"
)

// SSHChecker validates an SSH-related action by running sshd -t against the proposed config.
// This is a preflight check — it runs before any mutation.
// The Apply mutation guard also runs sshd -t after writing the file (belt-and-suspenders).
type SSHChecker struct{}

// NewSSHChecker creates an SSHChecker.
func NewSSHChecker() *SSHChecker {
	return &SSHChecker{}
}

func (c *SSHChecker) Check(ctx context.Context, action *model.PlannedAction, exec executor.Executor) (*SafetyResult, error) {
	if !isSSHModule(action.ModuleID) {
		return &SafetyResult{Safe: true}, nil
	}

	out, err := exec.RunReadOnly(ctx, "sshd", "-t")
	if err != nil {
		return &SafetyResult{
			Safe:   false,
			Reason: fmt.Sprintf("existing sshd config is already invalid (%s): manual fix required before hardener can proceed", strings.TrimSpace(out.Stderr)),
		}, nil
	}

	return &SafetyResult{
		Safe: true,
	}, nil
}

func isSSHModule(moduleID string) bool {
	return strings.HasPrefix(moduleID, "ssh-")
}
