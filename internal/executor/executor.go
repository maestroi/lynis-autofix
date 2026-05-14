package executor

import (
	"context"
	"io/fs"
)

// Executor extends Inspector with mutating operations.
// Used by Module.Apply() and Module.Rollback().
// LocalExecutor performs real syscalls; DryRunExecutor logs and no-ops.
type Executor interface {
	Inspector

	// Filesystem mutations
	WriteFile(ctx context.Context, path string, content []byte, mode fs.FileMode) error
	AppendFile(ctx context.Context, path string, content []byte) error
	SetFileMode(ctx context.Context, path string, mode fs.FileMode) error
	SetOwner(ctx context.Context, path string, uid, gid int) error

	// Kernel mutations
	SetSysctl(ctx context.Context, key, value string) error

	// Systemd mutations
	EnableService(ctx context.Context, name string) error
	DisableService(ctx context.Context, name string) error
	StartService(ctx context.Context, name string) error
	StopService(ctx context.Context, name string) error
	RestartService(ctx context.Context, name string) error

	// Package mutations
	InstallPackage(ctx context.Context, name string) error

	// Escape hatch for commands with no semantic method (e.g., sshd -t validation).
	Run(ctx context.Context, name string, args ...string) (CmdOutput, error)

	IsDryRun() bool
}
