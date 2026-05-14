package testhelpers

import (
	"context"
	"os"
	"strings"

	"github.com/maestroi/hardener/internal/executor"
)

// FakeInspector returns controlled read-only system state for tests.
// All fields are exported so tests can populate them directly.
type FakeInspector struct {
	Files         map[string][]byte
	Services      map[string]executor.ServiceStatus
	InstalledPkgs map[string]bool
	SysctlValues  map[string]string

	// RunReadOnlyFn optionally overrides RunReadOnly(). If nil, returns empty CmdOutput.
	RunReadOnlyFn func(name string, args ...string) (executor.CmdOutput, error)
}

func (f *FakeInspector) ReadFile(_ context.Context, path string) ([]byte, error) {
	if data, ok := f.Files[path]; ok {
		return data, nil
	}
	return nil, os.ErrNotExist
}

func (f *FakeInspector) FileExists(_ context.Context, path string) (bool, error) {
	_, ok := f.Files[path]
	return ok, nil
}

func (f *FakeInspector) GetSysctl(_ context.Context, key string) (string, error) {
	if v, ok := f.SysctlValues[key]; ok {
		return v, nil
	}
	return "", nil
}

func (f *FakeInspector) ServiceState(_ context.Context, name string) (executor.ServiceStatus, error) {
	if s, ok := f.Services[name]; ok {
		return s, nil
	}
	return executor.ServiceStatus{Name: name}, nil
}

func (f *FakeInspector) IsPackageInstalled(_ context.Context, name string) (bool, error) {
	return f.InstalledPkgs[name], nil
}

func (f *FakeInspector) RunReadOnly(_ context.Context, name string, args ...string) (executor.CmdOutput, error) {
	if f.RunReadOnlyFn != nil {
		return f.RunReadOnlyFn(name, args...)
	}
	return executor.CmdOutput{}, nil
}

// FakeExecutor embeds FakeInspector and records all mutations.
// Tests inspect the Recorded* slices after Apply/Rollback calls.
type FakeExecutor struct {
	FakeInspector

	// Recorded mutations — inspected by tests.
	WrittenFiles      map[string][]byte
	InstalledPackages []string
	EnabledServices   []string
	DisabledServices  []string
	StartedServices   []string
	StoppedServices   []string
	RestartedServices []string

	SetFileModeRecords map[string]os.FileMode

	// IsDryRunFlag controls IsDryRun().
	IsDryRunFlag bool

	// RunFn optionally overrides Run(). If nil, Run always returns empty CmdOutput, nil.
	RunFn func(name string, args ...string) (executor.CmdOutput, error)
}

// ReadFile checks WrittenFiles first (so Apply-then-Validate round-trips work),
// then falls back to FakeInspector.
func (f *FakeExecutor) ReadFile(ctx context.Context, path string) ([]byte, error) {
	if f.WrittenFiles != nil {
		if data, ok := f.WrittenFiles[path]; ok {
			return data, nil
		}
	}
	return f.FakeInspector.ReadFile(ctx, path)
}

func (f *FakeExecutor) FileExists(ctx context.Context, path string) (bool, error) {
	if f.WrittenFiles != nil {
		if _, ok := f.WrittenFiles[path]; ok {
			return true, nil
		}
	}
	return f.FakeInspector.FileExists(ctx, path)
}

func (f *FakeExecutor) WriteFile(_ context.Context, path string, content []byte, _ os.FileMode) error {
	if f.WrittenFiles == nil {
		f.WrittenFiles = make(map[string][]byte)
	}
	f.WrittenFiles[path] = content
	if f.Files == nil {
		f.Files = make(map[string][]byte)
	}
	f.Files[path] = content
	return nil
}

func (f *FakeExecutor) AppendFile(ctx context.Context, path string, content []byte) error {
	existing, _ := f.ReadFile(ctx, path)
	return f.WriteFile(ctx, path, append(existing, content...), 0)
}

func (f *FakeExecutor) SetFileMode(_ context.Context, path string, mode os.FileMode) error {
	if f.SetFileModeRecords == nil {
		f.SetFileModeRecords = make(map[string]os.FileMode)
	}
	f.SetFileModeRecords[path] = mode
	return nil
}
func (f *FakeExecutor) SetOwner(_ context.Context, _ string, _, _ int) error         { return nil }
func (f *FakeExecutor) SetSysctl(_ context.Context, _, _ string) error               { return nil }

func (f *FakeExecutor) EnableService(_ context.Context, name string) error {
	f.EnabledServices = append(f.EnabledServices, name)
	if f.Services == nil {
		f.Services = make(map[string]executor.ServiceStatus)
	}
	s := f.Services[name]
	s.Name = name
	s.Enabled = true
	f.Services[name] = s
	return nil
}

func (f *FakeExecutor) DisableService(_ context.Context, name string) error {
	f.DisabledServices = append(f.DisabledServices, name)
	return nil
}

func (f *FakeExecutor) StartService(_ context.Context, name string) error {
	f.StartedServices = append(f.StartedServices, name)
	if f.Services == nil {
		f.Services = make(map[string]executor.ServiceStatus)
	}
	s := f.Services[name]
	s.Name = name
	s.Active = true
	f.Services[name] = s
	return nil
}

func (f *FakeExecutor) StopService(_ context.Context, name string) error {
	f.StoppedServices = append(f.StoppedServices, name)
	return nil
}

func (f *FakeExecutor) RestartService(_ context.Context, name string) error {
	f.RestartedServices = append(f.RestartedServices, name)
	return nil
}

func (f *FakeExecutor) InstallPackage(_ context.Context, name string) error {
	f.InstalledPackages = append(f.InstalledPackages, name)
	if f.InstalledPkgs == nil {
		f.InstalledPkgs = make(map[string]bool)
	}
	f.InstalledPkgs[name] = true
	return nil
}

func (f *FakeExecutor) Run(_ context.Context, name string, args ...string) (executor.CmdOutput, error) {
	if f.RunFn != nil {
		return f.RunFn(name, args...)
	}
	return executor.CmdOutput{}, nil
}

func (f *FakeExecutor) IsDryRun() bool { return f.IsDryRunFlag }

// ContainsService returns true if name appears in slice.
func ContainsService(slice []string, name string) bool {
	for _, s := range slice {
		if s == name {
			return true
		}
	}
	return false
}

// FileContains returns true if the written file at path contains substr.
func (f *FakeExecutor) FileContains(path, substr string) bool {
	data, ok := f.WrittenFiles[path]
	if !ok {
		return false
	}
	return strings.Contains(string(data), substr)
}

// HasWritten returns true if path was written by this executor.
func (f *FakeExecutor) HasWritten(path string) bool {
	_, ok := f.WrittenFiles[path]
	return ok
}

// PackageInstalled is a helper for asserting InstallPackage was called.
func (f *FakeExecutor) PackageInstalled(name string) bool {
	for _, p := range f.InstalledPackages {
		if p == name {
			return true
		}
	}
	return false
}
