package executor

import (
	"context"
	"io/fs"
	"sync"
)

// RecordedAction logs a single call made to DryRunExecutor.
type RecordedAction struct {
	Method string
	Args   []string
}

// DryRunExecutor implements Executor with zero side effects.
// All mutating calls are logged to an in-memory action log.
// All read calls return safe synthetic values.
type DryRunExecutor struct {
	mu      sync.Mutex
	actions []RecordedAction
}

// NewDryRunExecutor creates a DryRunExecutor.
func NewDryRunExecutor() *DryRunExecutor {
	return &DryRunExecutor{}
}

func (e *DryRunExecutor) record(method string, args ...string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.actions = append(e.actions, RecordedAction{Method: method, Args: args})
}

// RecordedActions returns all calls made to this executor in order.
func (e *DryRunExecutor) RecordedActions() []RecordedAction {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]RecordedAction, len(e.actions))
	copy(out, e.actions)
	return out
}

// --- Inspector methods (read-only, return synthetic safe values) ---

func (e *DryRunExecutor) ReadFile(_ context.Context, path string) ([]byte, error) {
	return nil, nil // safe empty content
}

func (e *DryRunExecutor) FileExists(_ context.Context, path string) (bool, error) {
	return false, nil // conservative: assume absent
}

func (e *DryRunExecutor) GetSysctl(_ context.Context, key string) (string, error) {
	return "", nil
}

func (e *DryRunExecutor) ServiceState(_ context.Context, name string) (ServiceStatus, error) {
	return ServiceStatus{Name: name, Active: false, Enabled: false}, nil
}

func (e *DryRunExecutor) IsPackageInstalled(_ context.Context, name string) (bool, error) {
	return false, nil
}

func (e *DryRunExecutor) RunReadOnly(_ context.Context, name string, args ...string) (CmdOutput, error) {
	return CmdOutput{ExitCode: 0}, nil
}

// --- Executor mutating methods (logged, no-op) ---

func (e *DryRunExecutor) WriteFile(_ context.Context, path string, content []byte, mode fs.FileMode) error {
	e.record("WriteFile", path)
	return nil
}

func (e *DryRunExecutor) AppendFile(_ context.Context, path string, content []byte) error {
	e.record("AppendFile", path)
	return nil
}

func (e *DryRunExecutor) SetFileMode(_ context.Context, path string, mode fs.FileMode) error {
	e.record("SetFileMode", path)
	return nil
}

func (e *DryRunExecutor) SetOwner(_ context.Context, path string, uid, gid int) error {
	e.record("SetOwner", path)
	return nil
}

func (e *DryRunExecutor) SetSysctl(_ context.Context, key, value string) error {
	e.record("SetSysctl", key, value)
	return nil
}

func (e *DryRunExecutor) EnableService(_ context.Context, name string) error {
	e.record("EnableService", name)
	return nil
}

func (e *DryRunExecutor) DisableService(_ context.Context, name string) error {
	e.record("DisableService", name)
	return nil
}

func (e *DryRunExecutor) StartService(_ context.Context, name string) error {
	e.record("StartService", name)
	return nil
}

func (e *DryRunExecutor) StopService(_ context.Context, name string) error {
	e.record("StopService", name)
	return nil
}

func (e *DryRunExecutor) RestartService(_ context.Context, name string) error {
	e.record("RestartService", name)
	return nil
}

func (e *DryRunExecutor) InstallPackage(_ context.Context, name string) error {
	e.record("InstallPackage", name)
	return nil
}

func (e *DryRunExecutor) Run(_ context.Context, name string, args ...string) (CmdOutput, error) {
	e.record("Run", append([]string{name}, args...)...)
	return CmdOutput{ExitCode: 0}, nil
}

func (e *DryRunExecutor) IsDryRun() bool { return true }
