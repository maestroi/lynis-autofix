package executor

import "context"

// Inspector provides read-only access to system state.
// Used by Module.Plan() and Module.Validate() — no mutations permitted.
type Inspector interface {
	ReadFile(ctx context.Context, path string) ([]byte, error)
	FileExists(ctx context.Context, path string) (bool, error)
	GetSysctl(ctx context.Context, key string) (string, error)
	ServiceState(ctx context.Context, name string) (ServiceStatus, error)
	IsPackageInstalled(ctx context.Context, name string) (bool, error)
	RunReadOnly(ctx context.Context, name string, args ...string) (CmdOutput, error)
}
