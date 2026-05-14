package safety_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/maestroi/hardener/internal/executor"
	"github.com/maestroi/hardener/internal/model"
	"github.com/maestroi/hardener/internal/safety"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type sshExecStub struct {
	*executor.DryRunExecutor
	failSSH bool
}

func newSSHExecStub(failSSH bool) *sshExecStub {
	return &sshExecStub{DryRunExecutor: executor.NewDryRunExecutor(), failSSH: failSSH}
}

func (e *sshExecStub) RunReadOnly(ctx context.Context, name string, args ...string) (executor.CmdOutput, error) {
	if name == "sshd" && e.failSSH {
		return executor.CmdOutput{Stderr: "bad config", ExitCode: 1}, fmt.Errorf("sshd -t failed")
	}
	return e.DryRunExecutor.RunReadOnly(ctx, name, args...)
}

func TestSSHChecker_NonSSHModule_Skips(t *testing.T) {
	c := safety.NewSSHChecker()
	action := &model.PlannedAction{ModuleID: "kernel-sysctl"}
	res, err := c.Check(context.Background(), action, executor.NewDryRunExecutor())
	require.NoError(t, err)
	assert.True(t, res.Safe)
}

func TestSSHChecker_SSHModule_ValidConfig(t *testing.T) {
	c := safety.NewSSHChecker()
	action := &model.PlannedAction{ModuleID: "ssh-hardening"}
	res, err := c.Check(context.Background(), action, executor.NewDryRunExecutor())
	require.NoError(t, err)
	assert.True(t, res.Safe)
}

func TestSSHChecker_SSHModule_InvalidConfig(t *testing.T) {
	c := safety.NewSSHChecker()
	action := &model.PlannedAction{ModuleID: "ssh-hardening"}
	res, err := c.Check(context.Background(), action, newSSHExecStub(true))
	require.NoError(t, err)
	assert.False(t, res.Safe)
	assert.Contains(t, res.Reason, "invalid")
}
