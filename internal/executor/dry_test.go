package executor_test

import (
	"context"
	"testing"

	"github.com/maestroi/hardener/internal/executor"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDryRunExecutor_IsDryRun(t *testing.T) {
	e := executor.NewDryRunExecutor()
	assert.True(t, e.IsDryRun())
}

func TestDryRunExecutor_WriteFile_NoSideEffect(t *testing.T) {
	e := executor.NewDryRunExecutor()
	err := e.WriteFile(context.Background(), "/etc/ssh/sshd_config", []byte("content"), 0600)
	require.NoError(t, err)
	actions := e.RecordedActions()
	assert.Len(t, actions, 1)
	assert.Equal(t, "WriteFile", actions[0].Method)
	assert.Equal(t, "/etc/ssh/sshd_config", actions[0].Args[0])
}

func TestDryRunExecutor_SetSysctl_NoSideEffect(t *testing.T) {
	e := executor.NewDryRunExecutor()
	err := e.SetSysctl(context.Background(), "net.ipv4.tcp_syncookies", "1")
	require.NoError(t, err)
	actions := e.RecordedActions()
	assert.Len(t, actions, 1)
	assert.Equal(t, "SetSysctl", actions[0].Method)
}

func TestDryRunExecutor_ReadFile_ReturnsSynthetic(t *testing.T) {
	e := executor.NewDryRunExecutor()
	content, err := e.ReadFile(context.Background(), "/etc/does-not-exist")
	require.NoError(t, err)
	assert.Empty(t, content)
}

func TestDryRunExecutor_FileExists_ReturnsFalse(t *testing.T) {
	e := executor.NewDryRunExecutor()
	exists, err := e.FileExists(context.Background(), "/any/path")
	require.NoError(t, err)
	assert.False(t, exists)
}

func TestDryRunExecutor_ServiceState_ReturnsInactive(t *testing.T) {
	e := executor.NewDryRunExecutor()
	state, err := e.ServiceState(context.Background(), "ssh")
	require.NoError(t, err)
	assert.Equal(t, "ssh", state.Name)
}

func TestDryRunExecutor_RestartService_Recorded(t *testing.T) {
	e := executor.NewDryRunExecutor()
	err := e.RestartService(context.Background(), "ssh")
	require.NoError(t, err)
	actions := e.RecordedActions()
	assert.Equal(t, "RestartService", actions[0].Method)
	assert.Equal(t, "ssh", actions[0].Args[0])
}

func TestDryRunExecutor_Run_ReturnsEmptyOutput(t *testing.T) {
	e := executor.NewDryRunExecutor()
	out, err := e.Run(context.Background(), "sshd", "-t")
	require.NoError(t, err)
	assert.Equal(t, 0, out.ExitCode)
}

func TestDryRunExecutor_RecordedActions_Order(t *testing.T) {
	e := executor.NewDryRunExecutor()
	_ = e.WriteFile(context.Background(), "/a", nil, 0644)
	_ = e.SetSysctl(context.Background(), "key", "val")
	_ = e.RestartService(context.Background(), "ssh")
	actions := e.RecordedActions()
	assert.Equal(t, []string{"WriteFile", "SetSysctl", "RestartService"},
		[]string{actions[0].Method, actions[1].Method, actions[2].Method})
}
