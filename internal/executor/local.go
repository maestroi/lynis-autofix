package executor

import (
	"bytes"
	"context"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"strings"
)

// LocalExecutor implements Executor using real OS syscalls.
// Requires appropriate permissions (typically root) for system-level operations.
type LocalExecutor struct{}

// NewLocalExecutor creates a LocalExecutor.
func NewLocalExecutor() *LocalExecutor {
	return &LocalExecutor{}
}

// --- Inspector methods ---

func (e *LocalExecutor) ReadFile(_ context.Context, path string) ([]byte, error) {
	return os.ReadFile(path)
}

func (e *LocalExecutor) FileExists(_ context.Context, path string) (bool, error) {
	_, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	return err == nil, err
}

func (e *LocalExecutor) GetSysctl(ctx context.Context, key string) (string, error) {
	out, err := e.RunReadOnly(ctx, "sysctl", "-n", key)
	if err != nil {
		return "", fmt.Errorf("sysctl get %s: %w", key, err)
	}
	return strings.TrimSpace(out.Stdout), nil
}

func (e *LocalExecutor) ServiceState(_ context.Context, name string) (ServiceStatus, error) {
	activeOut, _ := runCommand("systemctl", "is-active", name)
	enabledOut, _ := runCommand("systemctl", "is-enabled", name)
	return ServiceStatus{
		Name:    name,
		Active:  strings.TrimSpace(activeOut.Stdout) == "active",
		Enabled: strings.TrimSpace(enabledOut.Stdout) == "enabled",
	}, nil
}

func (e *LocalExecutor) IsPackageInstalled(_ context.Context, name string) (bool, error) {
	out, err := runCommand("dpkg-query", "-W", "-f=${Status}", name)
	if err != nil {
		return false, nil // package not found
	}
	return strings.Contains(out.Stdout, "install ok installed"), nil
}

func (e *LocalExecutor) RunReadOnly(_ context.Context, name string, args ...string) (CmdOutput, error) {
	return runCommand(name, args...)
}

// --- Executor mutating methods ---

func (e *LocalExecutor) WriteFile(_ context.Context, path string, content []byte, mode fs.FileMode) error {
	return os.WriteFile(path, content, mode)
}

func (e *LocalExecutor) AppendFile(_ context.Context, path string, content []byte) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(content)
	return err
}

func (e *LocalExecutor) SetFileMode(_ context.Context, path string, mode fs.FileMode) error {
	return os.Chmod(path, mode)
}

func (e *LocalExecutor) SetOwner(_ context.Context, path string, uid, gid int) error {
	return os.Lchown(path, uid, gid)
}

func (e *LocalExecutor) SetSysctl(_ context.Context, key, value string) error {
	out, err := runCommand("sysctl", "-w", fmt.Sprintf("%s=%s", key, value))
	if err != nil {
		return fmt.Errorf("sysctl -w %s=%s: %s", key, value, out.Stderr)
	}
	return nil
}

func (e *LocalExecutor) EnableService(_ context.Context, name string) error {
	return runVoid("systemctl", "enable", name)
}

func (e *LocalExecutor) DisableService(_ context.Context, name string) error {
	return runVoid("systemctl", "disable", name)
}

func (e *LocalExecutor) StartService(_ context.Context, name string) error {
	return runVoid("systemctl", "start", name)
}

func (e *LocalExecutor) StopService(_ context.Context, name string) error {
	return runVoid("systemctl", "stop", name)
}

func (e *LocalExecutor) RestartService(_ context.Context, name string) error {
	return runVoid("systemctl", "restart", name)
}

func (e *LocalExecutor) InstallPackage(_ context.Context, name string) error {
	out, err := runCommand("apt-get", "install", "-y", name)
	if err != nil {
		return fmt.Errorf("apt-get install %s: %s", name, out.Stderr)
	}
	return nil
}

func (e *LocalExecutor) Run(_ context.Context, name string, args ...string) (CmdOutput, error) {
	return runCommand(name, args...)
}

func (e *LocalExecutor) IsDryRun() bool { return false }

// runCommand executes a command and returns its output. Returns an error if exit code != 0.
func runCommand(name string, args ...string) (CmdOutput, error) {
	cmd := exec.Command(name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()

	out := CmdOutput{
		Stdout:   stdout.String(),
		Stderr:   stderr.String(),
		ExitCode: 0,
	}
	if cmd.ProcessState != nil {
		out.ExitCode = cmd.ProcessState.ExitCode()
	}
	if err != nil {
		return out, fmt.Errorf("%s exited %d: %s", name, out.ExitCode, strings.TrimSpace(stderr.String()))
	}
	return out, nil
}

// runVoid runs a command and discards output, returning only the error.
func runVoid(name string, args ...string) error {
	_, err := runCommand(name, args...)
	return err
}
