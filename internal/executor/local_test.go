package executor_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/maestroi/hardener/internal/executor"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLocalExecutor_IsDryRun_False(t *testing.T) {
	e := executor.NewLocalExecutor()
	assert.False(t, e.IsDryRun())
}

func TestLocalExecutor_WriteFile_And_ReadFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "testfile")
	e := executor.NewLocalExecutor()

	err := e.WriteFile(context.Background(), path, []byte("hello\n"), 0600)
	require.NoError(t, err)

	content, err := e.ReadFile(context.Background(), path)
	require.NoError(t, err)
	assert.Equal(t, "hello\n", string(content))
}

func TestLocalExecutor_FileExists_True(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "exists")
	require.NoError(t, os.WriteFile(path, []byte("x"), 0644))

	e := executor.NewLocalExecutor()
	exists, err := e.FileExists(context.Background(), path)
	require.NoError(t, err)
	assert.True(t, exists)
}

func TestLocalExecutor_FileExists_False(t *testing.T) {
	e := executor.NewLocalExecutor()
	exists, err := e.FileExists(context.Background(), "/tmp/hardener-does-not-exist-xyz")
	require.NoError(t, err)
	assert.False(t, exists)
}

func TestLocalExecutor_SetFileMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "modefile")
	require.NoError(t, os.WriteFile(path, []byte("x"), 0644))

	e := executor.NewLocalExecutor()
	require.NoError(t, e.SetFileMode(context.Background(), path, 0600))

	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
}

func TestLocalExecutor_Run_EchoCommand(t *testing.T) {
	e := executor.NewLocalExecutor()
	out, err := e.Run(context.Background(), "echo", "hello")
	require.NoError(t, err)
	assert.Contains(t, out.Stdout, "hello")
	assert.Equal(t, 0, out.ExitCode)
}

func TestLocalExecutor_Run_NonZeroExitCode(t *testing.T) {
	e := executor.NewLocalExecutor()
	out, err := e.Run(context.Background(), "false")
	assert.Error(t, err)
	assert.Equal(t, 1, out.ExitCode)
}
