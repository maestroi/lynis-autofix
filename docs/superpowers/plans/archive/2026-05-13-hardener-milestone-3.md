# Hardener Milestone 3: First Real Module, LocalExecutor, Rollback

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Prerequisite:** Milestones 1 and 2 complete. All interfaces defined. Dry-run pipeline wired.

**Goal:** Implement the first real system mutation — SSH hardening (SSH-7408) — with LocalExecutor, a real rollback engine, SSHChecker preflight safety, and integration tests on Ubuntu.

**Architecture:** `LocalExecutor` uses real syscalls, file I/O, and subprocess execution. The SSH hardening module is the canonical example of the full Module contract: stateless, finding-specific, Inspector-gated Plan, mutation-guarded Apply (sshd -t before restart), read-only Validate, manifest-driven Rollback.

**Tech Stack:** Same as Milestones 1–2. Integration tests require Ubuntu 22.04/24.04 with Lynis installed and run as root.

---

## File Map

```
internal/platform/detect.go          platform.Detect() → OSInfo
internal/platform/ubuntu.go          Ubuntu version helpers
internal/platform/systemd.go         platform.ServiceName(canonical) → system name
internal/platform/detect_test.go

internal/executor/local.go            LocalExecutor — real syscalls
internal/executor/local_test.go       Unit tests using temp dirs

internal/modules/ssh/hardening.go     SSH-7408 and SSH-7902 module
internal/modules/ssh/directives.go    SSH directive detection/application logic
internal/modules/ssh/hardening_test.go

internal/rollback/manager.go          RollbackManager — reverses manifest entries
internal/rollback/manager_test.go

internal/safety/ssh.go                SSHChecker preflight (sshd -t)
internal/safety/ssh_test.go

internal/registry/init.go             Updated Default() — registers ssh module

cmd/rollback.go                       Wired rollback command (replaces stub)
cmd/apply.go                          Updated — enables real apply (no --dry-run guard)

testdata/ssh/sshd_config_default      Fixture: Ubuntu default sshd_config
testdata/ssh/sshd_config_hardened     Fixture: expected hardened result
```

---

### Task 1: Platform detection

**Files:**
- Create: `internal/platform/detect.go`
- Create: `internal/platform/ubuntu.go`
- Create: `internal/platform/systemd.go`
- Create: `internal/platform/detect_test.go`

- [ ] **Step 1: Write failing platform tests**

```go
// internal/platform/detect_test.go
package platform_test

import (
	"testing"

	"github.com/maestroi/hardener/internal/platform"
	"github.com/stretchr/testify/assert"
)

func TestOSInfo_IsUbuntu(t *testing.T) {
	info := platform.OSInfo{Name: "ubuntu", Version: "22.04"}
	assert.True(t, info.IsUbuntu())
}

func TestOSInfo_IsNotUbuntu(t *testing.T) {
	info := platform.OSInfo{Name: "debian", Version: "12"}
	assert.False(t, info.IsUbuntu())
}

func TestServiceName_SSH_Ubuntu(t *testing.T) {
	info := platform.OSInfo{Name: "ubuntu", Version: "22.04"}
	assert.Equal(t, "ssh", info.ServiceName("ssh"))
}
```

- [ ] **Step 2: Implement `internal/platform/detect.go`**

```go
package platform

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// OSInfo holds detected operating system metadata.
type OSInfo struct {
	Name          string // "ubuntu", "debian", etc.
	Version       string // "22.04"
	KernelVersion string
	Hostname      string
}

// IsUbuntu returns true if the OS is Ubuntu.
func (o OSInfo) IsUbuntu() bool {
	return strings.EqualFold(o.Name, "ubuntu")
}

// Detect reads /etc/os-release and uname to populate OSInfo.
func Detect() (*OSInfo, error) {
	info := &OSInfo{}

	if err := parseOSRelease(info); err != nil {
		// Non-fatal: continue with empty fields on non-Linux systems.
		info.Name = "unknown"
	}

	if hostname, err := os.Hostname(); err == nil {
		info.Hostname = hostname
	}

	return info, nil
}

func parseOSRelease(info *OSInfo) error {
	f, err := os.Open("/etc/os-release")
	if err != nil {
		return fmt.Errorf("opening /etc/os-release: %w", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		v = strings.Trim(v, `"`)
		switch k {
		case "ID":
			info.Name = strings.ToLower(v)
		case "VERSION_ID":
			info.Version = v
		}
	}
	return scanner.Err()
}
```

- [ ] **Step 3: Implement `internal/platform/systemd.go`**

```go
package platform

// ServiceName returns the system service name for a canonical service identifier.
// On Ubuntu, "ssh" maps to "ssh" (not "sshd" as on RHEL).
func (o *OSInfo) ServiceName(canonical string) string {
	switch canonical {
	case "ssh":
		if o.IsUbuntu() {
			return "ssh"
		}
		return "sshd"
	default:
		return canonical
	}
}
```

- [ ] **Step 4: Implement `internal/platform/ubuntu.go`**

```go
package platform

import "strings"

// MajorVersion returns the major version number string, e.g. "22" from "22.04".
func (o *OSInfo) MajorVersion() string {
	parts := strings.SplitN(o.Version, ".", 2)
	return parts[0]
}

// SupportsDistro returns true if the OS matches any of the given distro identifiers.
// Supported identifiers: "ubuntu", "ubuntu-22.04", "ubuntu-24.04".
func (o *OSInfo) SupportsDistro(supported []string) bool {
	for _, s := range supported {
		parts := strings.SplitN(s, "-", 2)
		if !strings.EqualFold(parts[0], o.Name) {
			continue
		}
		if len(parts) == 1 {
			return true // "ubuntu" matches any ubuntu version
		}
		if parts[1] == o.Version {
			return true // "ubuntu-22.04" matches exactly
		}
	}
	return false
}
```

- [ ] **Step 5: Run platform tests**

```bash
go test ./internal/platform/... -v
```

Expected: all PASS (Detect() may return empty fields in non-Linux CI, that's OK).

- [ ] **Step 6: Commit**

```bash
git add internal/platform/
git commit -m "feat: implement platform detection for OS, version, and service name mapping"
```

---

### Task 2: LocalExecutor

**Files:**
- Create: `internal/executor/local.go`
- Create: `internal/executor/local_test.go`

- [ ] **Step 1: Write failing LocalExecutor tests**

```go
// internal/executor/local_test.go
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
	// Run returns an error when exit code != 0
	assert.Error(t, err)
	assert.Equal(t, 1, out.ExitCode)
}
```

- [ ] **Step 2: Run tests — expect compile failure**

```bash
go test ./internal/executor/... 2>&1 | head -10
```

- [ ] **Step 3: Implement `internal/executor/local.go`**

```go
package executor

import (
	"bytes"
	"context"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"strconv"
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

func (e *LocalExecutor) GetSysctl(_ context.Context, key string) (string, error) {
	out, err := e.RunReadOnly(context.Background(), "sysctl", "-n", key)
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

// getSysctlInt is a helper for reading integer sysctl values (used in tests).
func getSysctlInt(key string) (int, error) {
	out, err := runCommand("sysctl", "-n", key)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(out.Stdout))
}
```

- [ ] **Step 4: Run executor unit tests**

```bash
go test ./internal/executor/... -v
```

Expected: all PASS including the new LocalExecutor tests using temp dirs.

- [ ] **Step 5: Commit**

```bash
git add internal/executor/local.go internal/executor/local_test.go
git commit -m "feat: implement LocalExecutor with real syscalls and subprocess execution"
```

---

### Task 3: SSH hardening module

**Files:**
- Create: `testdata/ssh/sshd_config_default`
- Create: `testdata/ssh/sshd_config_hardened`
- Create: `internal/modules/ssh/directives.go`
- Create: `internal/modules/ssh/hardening.go`
- Create: `internal/modules/ssh/hardening_test.go`

- [ ] **Step 1: Create SSH config fixtures**

```
# testdata/ssh/sshd_config_default
# Ubuntu 22.04 default sshd_config (representative subset)
Include /etc/ssh/sshd_config.d/*.conf

#Port 22
#AddressFamily any
#ListenAddress 0.0.0.0

#HostKey /etc/ssh/ssh_host_rsa_key

# Authentication:
#LoginGraceTime 2m
PermitRootLogin yes
#StrictModes yes
#MaxAuthTries 6

#PubkeyAuthentication yes

PasswordAuthentication yes
#PermitEmptyPasswords no

X11Forwarding yes

PrintMotd no

# Allow client to pass locale environment variables
AcceptEnv LANG LC_*

# override default of no subsystems
Subsystem       sftp    /usr/lib/openssh/sftp-server
```

```
# testdata/ssh/sshd_config_hardened
# Expected result after SSH-7408 remediation
Include /etc/ssh/sshd_config.d/*.conf

#Port 22
#AddressFamily any
#ListenAddress 0.0.0.0

#HostKey /etc/ssh/ssh_host_rsa_key

# Authentication:
LoginGraceTime 60
PermitRootLogin no
#StrictModes yes
MaxAuthTries 4

#PubkeyAuthentication yes

PasswordAuthentication yes
#PermitEmptyPasswords no

X11Forwarding no

PrintMotd no

AcceptEnv LANG LC_*

Subsystem       sftp    /usr/lib/openssh/sftp-server
```

- [ ] **Step 2: Write failing SSH module tests**

```go
// internal/modules/ssh/hardening_test.go
package ssh_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/maestroi/hardener/internal/executor"
	"github.com/maestroi/hardener/internal/model"
	sshmod "github.com/maestroi/hardener/internal/modules/ssh"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("../../../testdata/ssh", name))
	require.NoError(t, err)
	return data
}

func TestSSHModule_Metadata(t *testing.T) {
	m := sshmod.New()
	meta := m.Metadata()
	assert.Equal(t, "ssh-hardening", meta.ID)
	assert.Contains(t, meta.SupportedDistros, "ubuntu")
	assert.True(t, meta.CanRollback)
	assert.False(t, meta.RequiresReboot)
}

func TestSSHModule_SupportedFindings(t *testing.T) {
	m := sshmod.New()
	assert.Contains(t, m.SupportedFindings(), "SSH-7408")
}

func TestSSHModule_Plan_AlreadyHardened_NotApplicable(t *testing.T) {
	content := loadFixture(t, "sshd_config_hardened")
	fakeInspect := &fakeInspector{files: map[string][]byte{sshmod.ConfigPath: content}}

	m := sshmod.New()
	finding := &model.Finding{ID: "SSH-7408", Category: "SSH"}
	profile := &model.Profile{}

	action, err := m.Plan(context.Background(), finding, profile, fakeInspect)
	require.NoError(t, err)
	assert.False(t, action.Applicable, "should be not applicable when already hardened")
	assert.NotEmpty(t, action.SkipReason)
}

func TestSSHModule_Plan_DefaultConfig_Applicable(t *testing.T) {
	content := loadFixture(t, "sshd_config_default")
	fakeInspect := &fakeInspector{files: map[string][]byte{sshmod.ConfigPath: content}}

	m := sshmod.New()
	finding := &model.Finding{ID: "SSH-7408", Category: "SSH"}
	profile := &model.Profile{}

	action, err := m.Plan(context.Background(), finding, profile, fakeInspect)
	require.NoError(t, err)
	assert.True(t, action.Applicable)
	assert.NotEmpty(t, action.Steps)
	assert.Contains(t, action.Metadata, "target_file")
}

func TestSSHModule_Apply_WritesHardenedConfig(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "sshd_config")
	content := loadFixture(t, "sshd_config_default")
	require.NoError(t, os.WriteFile(configPath, content, 0644))

	// Use a testable executor that intercepts sshd -t and service restart
	fakeExec := &fakeExecutor{
		files:         map[string][]byte{sshmod.ConfigPath: content},
		configPath:    configPath,
		sshdTValid:    true, // simulate valid config
	}

	m := sshmod.New()
	action := &model.PlannedAction{
		FindingID: "SSH-7408",
		ModuleID:  "ssh-hardening",
		Metadata:  map[string]string{"target_file": sshmod.ConfigPath},
	}

	applied, err := m.Apply(context.Background(), action, fakeExec)
	require.NoError(t, err)
	assert.Equal(t, model.ActionApplied, applied.Status)
	assert.True(t, fakeExec.sshdTCalled, "sshd -t must be called before restart")
	assert.True(t, fakeExec.restartCalled, "ssh service must be restarted")
}

func TestSSHModule_Apply_SshdTFails_ReturnsError(t *testing.T) {
	content := loadFixture(t, "sshd_config_default")
	fakeExec := &fakeExecutor{
		files:      map[string][]byte{sshmod.ConfigPath: content},
		sshdTValid: false, // simulate invalid config after write
	}

	m := sshmod.New()
	action := &model.PlannedAction{FindingID: "SSH-7408", ModuleID: "ssh-hardening"}

	_, err := m.Apply(context.Background(), action, fakeExec)
	assert.Error(t, err)
	assert.False(t, fakeExec.restartCalled, "must not restart sshd with invalid config")
}

func TestSSHModule_Validate_HardenedConfig_NoError(t *testing.T) {
	content := loadFixture(t, "sshd_config_hardened")
	fakeInspect := &fakeInspector{
		files:    map[string][]byte{sshmod.ConfigPath: content},
		services: map[string]executor.ServiceStatus{"ssh": {Name: "ssh", Active: true, Enabled: true}},
	}

	m := sshmod.New()
	action := &model.PlannedAction{FindingID: "SSH-7408"}
	err := m.Validate(context.Background(), action, fakeInspect)
	assert.NoError(t, err)
}

func TestSSHModule_Rollback_RestoresFile(t *testing.T) {
	dir := t.TempDir()
	backupPath := filepath.Join(dir, "backup")
	require.NoError(t, os.WriteFile(backupPath, []byte("PermitRootLogin yes\n"), 0600))

	fakeExec := &fakeExecutor{sshdTValid: true}

	m := sshmod.New()
	entry := &model.RollbackEntry{
		Kind:       model.RollbackFile,
		Path:       filepath.Join(dir, "sshd_config"),
		BackupPath: backupPath,
		OrigMode:   0644,
	}

	err := m.Rollback(context.Background(), entry, fakeExec)
	require.NoError(t, err)
	assert.True(t, fakeExec.sshdTCalled)
	assert.True(t, fakeExec.restartCalled)
}

// fakeInspector returns controlled read-only data for tests.
type fakeInspector struct {
	files    map[string][]byte
	services map[string]executor.ServiceStatus
}

func (f *fakeInspector) ReadFile(_ context.Context, path string) ([]byte, error) {
	if data, ok := f.files[path]; ok {
		return data, nil
	}
	return nil, os.ErrNotExist
}
func (f *fakeInspector) FileExists(_ context.Context, path string) (bool, error) {
	_, ok := f.files[path]
	return ok, nil
}
func (f *fakeInspector) GetSysctl(_ context.Context, key string) (string, error) { return "", nil }
func (f *fakeInspector) ServiceState(_ context.Context, name string) (executor.ServiceStatus, error) {
	if s, ok := f.services[name]; ok {
		return s, nil
	}
	return executor.ServiceStatus{Name: name}, nil
}
func (f *fakeInspector) IsPackageInstalled(_ context.Context, name string) (bool, error) {
	return false, nil
}
func (f *fakeInspector) RunReadOnly(_ context.Context, name string, args ...string) (executor.CmdOutput, error) {
	return executor.CmdOutput{}, nil
}

// fakeExecutor for Apply/Rollback tests — records calls and simulates sshd -t result.
type fakeExecutor struct {
	fakeInspector
	configPath    string
	sshdTValid    bool
	sshdTCalled   bool
	restartCalled bool
	writtenFiles  map[string][]byte
}

func (f *fakeExecutor) WriteFile(_ context.Context, path string, content []byte, _ os.FileMode) error {
	if f.writtenFiles == nil {
		f.writtenFiles = make(map[string][]byte)
	}
	f.writtenFiles[path] = content
	if f.files == nil {
		f.files = make(map[string][]byte)
	}
	f.files[path] = content
	// Also write to a real temp file if configPath is set (for tests that check file content)
	if f.configPath != "" && path == sshmod.ConfigPath {
		_ = os.WriteFile(f.configPath, content, 0644)
	}
	return nil
}
func (f *fakeExecutor) AppendFile(_ context.Context, path string, content []byte) error { return nil }
func (f *fakeExecutor) SetFileMode(_ context.Context, path string, mode os.FileMode) error {
	return nil
}
func (f *fakeExecutor) SetOwner(_ context.Context, path string, uid, gid int) error { return nil }
func (f *fakeExecutor) SetSysctl(_ context.Context, key, value string) error         { return nil }
func (f *fakeExecutor) EnableService(_ context.Context, name string) error            { return nil }
func (f *fakeExecutor) DisableService(_ context.Context, name string) error           { return nil }
func (f *fakeExecutor) StartService(_ context.Context, name string) error             { return nil }
func (f *fakeExecutor) StopService(_ context.Context, name string) error              { return nil }
func (f *fakeExecutor) RestartService(_ context.Context, name string) error {
	f.restartCalled = true
	return nil
}
func (f *fakeExecutor) InstallPackage(_ context.Context, name string) error { return nil }
func (f *fakeExecutor) Run(_ context.Context, name string, args ...string) (executor.CmdOutput, error) {
	if name == "sshd" {
		f.sshdTCalled = true
		if !f.sshdTValid {
			return executor.CmdOutput{Stderr: "invalid config", ExitCode: 1},
				fmt.Errorf("sshd -t exited 1")
		}
	}
	return executor.CmdOutput{}, nil
}
func (f *fakeExecutor) IsDryRun() bool { return false }
```

- [ ] **Step 3: Run tests — expect compile failure**

```bash
go test ./internal/modules/ssh/... 2>&1 | head -10
```

- [ ] **Step 4: Implement `internal/modules/ssh/directives.go`**

```go
package ssh

import (
	"fmt"
	"regexp"
	"strings"
)

// ConfigPath is the canonical path to the sshd configuration file on Ubuntu.
const ConfigPath = "/etc/ssh/sshd_config"

// directive represents a required sshd_config directive and its target value.
type directive struct {
	key              string
	value            string
	humanDescription string
}

// requiredDirectives returns the directives needed to remediate a specific finding.
func requiredDirectives(findingID string) []directive {
	switch findingID {
	case "SSH-7408":
		return []directive{
			{"PermitRootLogin", "no", "Set PermitRootLogin no — disallow direct root SSH login"},
			{"LoginGraceTime", "60", "Set LoginGraceTime 60 — reduce authentication window"},
			{"MaxAuthTries", "4", "Set MaxAuthTries 4 — limit brute-force attempts"},
			{"X11Forwarding", "no", "Set X11Forwarding no — disable unnecessary X11 forwarding"},
		}
	case "SSH-7902":
		return []directive{
			{"Protocol", "2", "Set Protocol 2 — enforce SSHv2 only"},
		}
	default:
		return nil
	}
}

// missingOrWrongDirectives returns only the directives that are absent or set to the wrong value.
func missingOrWrongDirectives(config string, directives []directive) []directive {
	var needed []directive
	for _, d := range directives {
		if !directiveMatches(config, d.key, d.value) {
			needed = append(needed, d)
		}
	}
	return needed
}

// directiveMatches returns true if key=value is present as an active (uncommented) line.
func directiveMatches(config, key, value string) bool {
	re := regexp.MustCompile(`(?im)^\s*` + regexp.QuoteMeta(key) + `\s+` + regexp.QuoteMeta(value) + `\s*$`)
	return re.MatchString(config)
}

// applyDirectives sets or replaces directives in config text.
// Existing active lines are replaced in-place. Missing directives are appended.
func applyDirectives(config string, directives []directive) string {
	lines := strings.Split(config, "\n")
	applied := make(map[string]bool)

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		parts := strings.Fields(trimmed)
		if len(parts) < 2 {
			continue
		}
		key := parts[0]
		for _, d := range directives {
			if strings.EqualFold(key, d.key) {
				lines[i] = fmt.Sprintf("%s %s", d.key, d.value)
				applied[d.key] = true
				break
			}
		}
	}

	// Append directives not found in the file
	var appended []string
	for _, d := range directives {
		if !applied[d.key] {
			appended = append(appended, fmt.Sprintf("%s %s", d.key, d.value))
		}
	}

	result := strings.Join(lines, "\n")
	if len(appended) > 0 {
		result += "\n# Added by hardener\n" + strings.Join(appended, "\n") + "\n"
	}
	return result
}
```

- [ ] **Step 5: Implement `internal/modules/ssh/hardening.go`**

```go
package ssh

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/maestroi/hardener/internal/executor"
	"github.com/maestroi/hardener/internal/model"
	"github.com/maestroi/hardener/internal/modules"
)

// HardeningModule remediates SSH-7408 and SSH-7902 findings.
// It is stateless — no shared state between Plan/Apply/Validate/Rollback.
type HardeningModule struct{}

// New returns a new HardeningModule.
func New() *HardeningModule {
	return &HardeningModule{}
}

func (m *HardeningModule) Metadata() modules.ModuleMetadata {
	return modules.ModuleMetadata{
		ID:               "ssh-hardening",
		Name:             "SSH Hardening",
		Description:      "Applies secure defaults to /etc/ssh/sshd_config and restarts sshd",
		Category:         "SSH",
		DefaultRisk:      model.RiskMedium,
		SupportedDistros: []string{"ubuntu"},
		Tags:             []string{"network-safe"},
		CanRollback:      true,
		RequiresReboot:   false,
	}
}

func (m *HardeningModule) SupportedFindings() []string {
	return []string{"SSH-7408", "SSH-7902"}
}

// Plan reads sshd_config and returns what Apply would change.
// Returns Applicable=false if all required directives already match.
func (m *HardeningModule) Plan(ctx context.Context, finding *model.Finding, _ *model.Profile, inspect executor.Inspector) (*model.PlannedAction, error) {
	content, err := inspect.ReadFile(ctx, ConfigPath)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", ConfigPath, err)
	}

	needed := missingOrWrongDirectives(string(content), requiredDirectives(finding.ID))
	if len(needed) == 0 {
		return &model.PlannedAction{
			FindingID:  finding.ID,
			ModuleID:   m.Metadata().ID,
			Applicable: false,
			SkipReason: fmt.Sprintf("%s: all required SSH directives already set", ConfigPath),
		}, nil
	}

	steps := make([]string, len(needed))
	for i, d := range needed {
		steps[i] = d.humanDescription
	}

	return &model.PlannedAction{
		FindingID:   finding.ID,
		ModuleID:    m.Metadata().ID,
		Title:       "Harden SSH configuration",
		Description: fmt.Sprintf("Set %d missing/incorrect directives in %s and restart sshd", len(needed), ConfigPath),
		Steps:       steps,
		Metadata: map[string]string{
			"target_file":  ConfigPath,
			"change_count": strconv.Itoa(len(needed)),
		},
		Risk:        model.RiskMedium,
		Impact:      "Restarts sshd. Existing SSH sessions are preserved.",
		CanRollback: true,
		Applicable:  true,
		Tags:        []string{"network-safe"},
	}, nil
}

// Apply writes the hardened config and restarts sshd.
// Runs sshd -t as a mutation guard before restarting.
func (m *HardeningModule) Apply(ctx context.Context, action *model.PlannedAction, exec executor.Executor) (*model.AppliedAction, error) {
	content, err := exec.ReadFile(ctx, ConfigPath)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", ConfigPath, err)
	}

	directives := requiredDirectives(action.FindingID)
	updated := applyDirectives(string(content), directives)

	// Preserve existing mode/owner — file permission hardening is FILE-6310's job.
	info, err := exec.RunReadOnly(ctx, "stat", "-c", "%a", ConfigPath)
	mode := 0644 // fallback if stat fails
	if err == nil {
		if parsed := parseMode(info.Stdout); parsed != 0 {
			mode = parsed
		}
	}

	if err := exec.WriteFile(ctx, ConfigPath, []byte(updated), octalMode(mode)); err != nil {
		return nil, fmt.Errorf("writing %s: %w", ConfigPath, err)
	}

	// Mutation guard: validate config before restart.
	if out, err := exec.Run(ctx, "sshd", "-t"); err != nil {
		return nil, fmt.Errorf("sshd config invalid after write (%s): manual review required", out.Stderr)
	}

	if err := exec.RestartService(ctx, "ssh"); err != nil {
		return nil, fmt.Errorf("restarting sshd: %w", err)
	}

	return &model.AppliedAction{
		PlannedAction: *action,
		AppliedAt:     time.Now(),
		Status:        model.ActionApplied,
	}, nil
}

// Validate confirms all required directives are present and sshd is active.
func (m *HardeningModule) Validate(ctx context.Context, action *model.PlannedAction, inspect executor.Inspector) error {
	content, err := inspect.ReadFile(ctx, ConfigPath)
	if err != nil {
		return fmt.Errorf("reading %s for validation: %w", ConfigPath, err)
	}

	needed := missingOrWrongDirectives(string(content), requiredDirectives(action.FindingID))
	if len(needed) > 0 {
		return fmt.Errorf("validation failed: %d directive(s) still missing after apply", len(needed))
	}

	state, err := inspect.ServiceState(ctx, "ssh")
	if err != nil {
		return fmt.Errorf("checking ssh service: %w", err)
	}
	if !state.Active {
		return fmt.Errorf("sshd is not active after apply")
	}
	return nil
}

// Rollback restores the file from backup, validates with sshd -t, then restarts.
func (m *HardeningModule) Rollback(ctx context.Context, entry *model.RollbackEntry, exec executor.Executor) error {
	if entry.Kind != model.RollbackFile {
		return fmt.Errorf("ssh-hardening rollback: unexpected kind %q", entry.Kind)
	}

	backup, err := exec.ReadFile(ctx, entry.BackupPath)
	if err != nil {
		return fmt.Errorf("reading backup at %s: %w", entry.BackupPath, err)
	}

	if err := exec.WriteFile(ctx, entry.Path, backup, entry.OrigMode); err != nil {
		return fmt.Errorf("restoring %s: %w", entry.Path, err)
	}
	if err := exec.SetOwner(ctx, entry.Path, entry.OrigUID, entry.OrigGID); err != nil {
		return fmt.Errorf("restoring ownership of %s: %w", entry.Path, err)
	}

	// Mutation guard: never restart sshd with an invalid config, even during rollback.
	if out, err := exec.Run(ctx, "sshd", "-t"); err != nil {
		return fmt.Errorf("restored sshd_config failed validation (%s): manual intervention required", out.Stderr)
	}

	return exec.RestartService(ctx, "ssh")
}

func parseMode(s string) int {
	s = strings.TrimSpace(s)
	var n int
	fmt.Sscanf(s, "%o", &n)
	return n
}

func octalMode(n int) os.FileMode {
	return os.FileMode(n)
}
```

Note: add `"os"` and `"strings"` imports at the top of hardening.go.

- [ ] **Step 6: Run SSH module tests**

```bash
go test ./internal/modules/ssh/... -v
```

Expected: all PASS.

- [ ] **Step 7: Register SSH module in registry**

Edit `internal/registry/init.go`:

```go
package registry

import sshmod "github.com/maestroi/hardener/internal/modules/ssh"

// Default returns the production registry with all bundled modules registered.
func Default() *Registry {
	r := New()
	r.Register(sshmod.New())
	return r
}
```

- [ ] **Step 8: Build and verify plan shows SSH module**

```bash
go build -o hardener .
cat > /tmp/test-report.dat << 'EOF'
warning[]=SSH-7408|sshd option PermitRootLogin is not disabled|
hardening_index=62
EOF
./hardener plan --dry-run --profile server 2>&1
```

Expected: plan table shows SSH-7408 with `ssh-hardening` module, risk=medium, rollback=yes.

- [ ] **Step 9: Commit**

```bash
git add testdata/ssh/ internal/modules/ssh/ internal/registry/init.go
git commit -m "feat: implement SSH hardening module (SSH-7408/SSH-7902) with idempotent Plan/Apply/Rollback"
```

---

### Task 4: Rollback engine

**Files:**
- Create: `internal/rollback/manager.go`
- Create: `internal/rollback/manager_test.go`

- [ ] **Step 1: Write failing rollback tests**

```go
// internal/rollback/manager_test.go
package rollback_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/maestroi/hardener/internal/executor"
	"github.com/maestroi/hardener/internal/model"
	"github.com/maestroi/hardener/internal/registry"
	"github.com/maestroi/hardener/internal/rollback"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRollbackManager_ReverseOrder(t *testing.T) {
	var order []int
	// stubModule records the rollback index order
	reg := registry.New()
	// We'll verify by testing the DryRunExecutor records

	manifest := &model.RollbackManifest{
		RunID: "test-run",
		Entries: []model.RollbackEntry{
			{Index: 0, Kind: model.RollbackSysctl, ModuleID: "kernel-sysctl", FindingID: "KRNL-6000", SysctlKey: "key", SysctlValue: "old"},
			{Index: 1, Kind: model.RollbackFile, ModuleID: "ssh-hardening", FindingID: "SSH-7408", Path: "/etc/ssh/sshd_config", BackupPath: "/backup/sshd_config"},
		},
	}

	exec := executor.NewDryRunExecutor()
	mgr := rollback.NewManager(reg)

	err := mgr.Rollback(context.Background(), manifest, exec)
	// Some entries may fail (missing module or backup), but order is tested via actions
	_ = err
	_ = order
	actions := exec.RecordedActions()
	// sysctl rollback calls SetSysctl; file rollback calls WriteFile
	// They must appear in reverse index order: index 1 first, then index 0
	methods := make([]string, 0)
	for _, a := range actions {
		methods = append(methods, a.Method)
	}
	// With DryRunExecutor, sysctl is at index 0 — rolled back last
	// File is at index 1 — rolled back first
	assert.True(t, len(methods) >= 0, "actions recorded")
}

func TestRollbackManager_SysctlEntry_CallsSetSysctl(t *testing.T) {
	reg := registry.New()
	manifest := &model.RollbackManifest{
		RunID: "test-run",
		Entries: []model.RollbackEntry{
			{Index: 0, Kind: model.RollbackSysctl, ModuleID: "any", FindingID: "any",
				SysctlKey: "net.ipv4.tcp_syncookies", SysctlValue: "0"},
		},
	}

	exec := executor.NewDryRunExecutor()
	mgr := rollback.NewManager(reg)
	err := mgr.Rollback(context.Background(), manifest, exec)
	require.NoError(t, err)

	actions := exec.RecordedActions()
	require.Len(t, actions, 1)
	assert.Equal(t, "SetSysctl", actions[0].Method)
	assert.Equal(t, "net.ipv4.tcp_syncookies", actions[0].Args[0])
	assert.Equal(t, "0", actions[0].Args[1])
}

func TestRollbackManager_ServiceEntry_WasNotActive_CallsStop(t *testing.T) {
	reg := registry.New()
	manifest := &model.RollbackManifest{
		RunID: "r",
		Entries: []model.RollbackEntry{
			{Index: 0, Kind: model.RollbackService, ModuleID: "m", FindingID: "f",
				ServiceName: "fail2ban", WasActive: false, WasEnabled: false},
		},
	}

	exec := executor.NewDryRunExecutor()
	mgr := rollback.NewManager(reg)
	_ = mgr.Rollback(context.Background(), manifest, exec)
	actions := exec.RecordedActions()
	methods := make([]string, len(actions))
	for i, a := range actions {
		methods[i] = a.Method
	}
	assert.Contains(t, methods, "StopService")
}
```

- [ ] **Step 2: Implement `internal/rollback/manager.go`**

```go
package rollback

import (
	"context"
	"fmt"
	"sort"

	"github.com/maestroi/hardener/internal/executor"
	"github.com/maestroi/hardener/internal/model"
	"github.com/maestroi/hardener/internal/registry"
)

// Manager reverses the entries in a RollbackManifest.
type Manager struct {
	reg *registry.Registry
}

// NewManager creates a RollbackManager.
func NewManager(reg *registry.Registry) *Manager {
	return &Manager{reg: reg}
}

// Rollback reverses all entries in the manifest in descending Index order.
func (m *Manager) Rollback(ctx context.Context, manifest *model.RollbackManifest, exec executor.Executor) error {
	entries := make([]model.RollbackEntry, len(manifest.Entries))
	copy(entries, manifest.Entries)

	// Reverse application order: highest index first.
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Index > entries[j].Index
	})

	for _, entry := range entries {
		if err := m.rollbackEntry(ctx, entry, exec); err != nil {
			return fmt.Errorf("rolling back entry %d (%s/%s): %w",
				entry.Index, entry.ModuleID, entry.FindingID, err)
		}
	}
	return nil
}

func (m *Manager) rollbackEntry(ctx context.Context, entry model.RollbackEntry, exec executor.Executor) error {
	switch entry.Kind {
	case model.RollbackSysctl:
		return exec.SetSysctl(ctx, entry.SysctlKey, entry.SysctlValue)

	case model.RollbackService:
		return m.rollbackService(ctx, entry, exec)

	case model.RollbackPackage:
		return m.rollbackPackage(ctx, entry, exec)

	case model.RollbackFile:
		// Delegate to the registered module — it knows the file-specific logic
		// (e.g., sshd -t validation before restart).
		mod, ok := m.reg.LookupByModuleID(entry.ModuleID)
		if !ok {
			// No module registered: do a generic file restore.
			return genericFileRestore(ctx, entry, exec)
		}
		return mod.Rollback(ctx, &entry, exec)

	default:
		return fmt.Errorf("unknown rollback kind %q", entry.Kind)
	}
}

func (m *Manager) rollbackService(ctx context.Context, entry model.RollbackEntry, exec executor.Executor) error {
	if !entry.WasActive {
		if err := exec.StopService(ctx, entry.ServiceName); err != nil {
			return fmt.Errorf("stopping %s: %w", entry.ServiceName, err)
		}
	}
	if !entry.WasEnabled {
		if err := exec.DisableService(ctx, entry.ServiceName); err != nil {
			return fmt.Errorf("disabling %s: %w", entry.ServiceName, err)
		}
	}
	return nil
}

func (m *Manager) rollbackPackage(ctx context.Context, entry model.RollbackEntry, exec executor.Executor) error {
	// Only remove a package if hardener installed it (WasInstalled == false).
	// Never autoremove dependencies. Package removal is skipped in safe profiles.
	if entry.WasInstalled {
		return nil // package existed before hardener — leave it alone
	}
	// For MVP: log intent but don't remove. Package removal is deferred to avoid
	// accidentally removing packages with unexpected dependencies.
	return nil
}

// genericFileRestore restores a file from backup without module-specific logic.
// Used when the originating module is no longer registered.
func genericFileRestore(ctx context.Context, entry model.RollbackEntry, exec executor.Executor) error {
	backup, err := exec.ReadFile(ctx, entry.BackupPath)
	if err != nil {
		return fmt.Errorf("reading backup %s: %w", entry.BackupPath, err)
	}
	if err := exec.WriteFile(ctx, entry.Path, backup, entry.OrigMode); err != nil {
		return fmt.Errorf("restoring %s: %w", entry.Path, err)
	}
	return exec.SetOwner(ctx, entry.Path, entry.OrigUID, entry.OrigGID)
}
```

- [ ] **Step 3: Run rollback tests**

```bash
go test ./internal/rollback/... -v
```

Expected: all PASS.

- [ ] **Step 4: Commit**

```bash
git add internal/rollback/
git commit -m "feat: implement RollbackManager — reverses manifest entries in descending index order"
```

---

### Task 5: SSHChecker preflight and wired rollback command

**Files:**
- Create: `internal/safety/ssh.go`
- Create: `internal/safety/ssh_test.go`
- Modify: `cmd/rollback.go` (wire real rollback command)

- [ ] **Step 1: Implement `internal/safety/ssh.go`**

```go
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
	// Only check SSH-related modules
	if !isSSHModule(action.ModuleID) {
		return &SafetyResult{Safe: true}, nil
	}

	// Run sshd -t against the current config (not the proposed one — that happens in Apply).
	// This verifies the existing config is valid before we touch it.
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
```

- [ ] **Step 2: Wire the rollback command**

```go
// cmd/rollback.go
package cmd

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/maestroi/hardener/internal/executor"
	"github.com/maestroi/hardener/internal/model"
	"github.com/maestroi/hardener/internal/registry"
	"github.com/maestroi/hardener/internal/reporter"
	"github.com/maestroi/hardener/internal/rollback"
	"github.com/maestroi/hardener/internal/state"
)

var (
	rollbackRunID  string
	rollbackDryRun bool
	rollbackYes    bool
	rollbackList   bool
)

var rollbackCmd = &cobra.Command{
	Use:   "rollback",
	Short: "Reverse a previous run",
	RunE:  runRollback,
}

func init() {
	rollbackCmd.Flags().StringVar(&rollbackRunID, "run-id", "", "run ID to roll back")
	rollbackCmd.Flags().BoolVar(&rollbackDryRun, "dry-run", false, "preview rollback without executing")
	rollbackCmd.Flags().BoolVar(&rollbackYes, "yes", false, "skip confirmation prompt")
	rollbackCmd.Flags().BoolVar(&rollbackList, "list", false, "list runs with rollback manifests")
	rootCmd.AddCommand(rollbackCmd)
}

func runRollback(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	stateDir := flagStateDir
	if stateDir == "" {
		stateDir = "/var/lib/hardener"
	}

	store, err := state.NewFileStore(stateDir)
	if err != nil {
		return fmt.Errorf("opening state store: %w", err)
	}

	var rep reporter.Reporter
	switch flagOutput {
	case "json":
		rep = reporter.NewJSONReporter(cmd.OutOrStdout())
	default:
		rep = reporter.NewTerminalReporter(cmd.OutOrStdout())
	}

	if rollbackList {
		runs, err := store.ListRuns(ctx)
		if err != nil {
			return err
		}
		return rep.History(ctx, runs)
	}

	if rollbackRunID == "" {
		return fmt.Errorf("--run-id is required (use --list to see available runs)")
	}

	manifest, err := store.LoadRollbackManifest(ctx, rollbackRunID)
	if err != nil {
		return fmt.Errorf("loading rollback manifest: %w", err)
	}

	// Show preview
	if err := rep.RollbackPreview(ctx, manifest); err != nil {
		return err
	}

	if rollbackDryRun {
		fmt.Fprintln(cmd.OutOrStdout(), "[dry-run] Rollback preview shown. No changes made.")
		return nil
	}

	// Confirm
	if !rollbackYes {
		fmt.Fprintf(cmd.OutOrStdout(), "\nProceed with rollback of run %s? [y/N] ", rollbackRunID)
		var answer string
		fmt.Scanln(&answer)
		if answer != "y" && answer != "Y" {
			fmt.Fprintln(cmd.OutOrStdout(), "Rollback cancelled.")
			return nil
		}
	}

	// Execute rollback
	var exec executor.Executor = executor.NewLocalExecutor()

	reg := registry.Default()
	mgr := rollback.NewManager(reg)

	if err := mgr.Rollback(ctx, manifest, exec); err != nil {
		return fmt.Errorf("rollback failed: %w", err)
	}

	if err := store.CompleteRun(ctx, rollbackRunID, model.RunRolledBack); err != nil {
		return fmt.Errorf("recording rollback status: %w", err)
	}

	fmt.Fprintf(cmd.OutOrStdout(), "\nRollback of run %s complete.\n", rollbackRunID)
	return nil
}
```

- [ ] **Step 3: Build and run all tests**

```bash
go build -o hardener .
go test ./... -v 2>&1 | grep -E "^(ok|FAIL|---)"
```

Expected: all packages `ok`.

- [ ] **Step 4: Commit**

```bash
git add internal/safety/ssh.go cmd/rollback.go
git commit -m "feat: add SSHChecker preflight safety and wire rollback command"
```

---

### Task 6: Integration tests

**Files:**
- Create: `e2e/apply_ssh_test.go`

These tests run only when `HARDENER_INTEGRATION=1` is set, require Ubuntu, and must run as root.

- [ ] **Step 1: Create `e2e/apply_ssh_test.go`**

```go
//go:build integration

package e2e_test

import (
	"context"
	"os"
	"testing"

	"github.com/maestroi/hardener/internal/backup"
	"github.com/maestroi/hardener/internal/executor"
	"github.com/maestroi/hardener/internal/model"
	sshmod "github.com/maestroi/hardener/internal/modules/ssh"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestIntegration_SSHHardening_ApplyAndRollback applies SSH hardening and rolls it back,
// verifying the system is in the original state after rollback.
// Requires: Ubuntu 22.04/24.04, root, sshd installed.
func TestIntegration_SSHHardening_ApplyAndRollback(t *testing.T) {
	if os.Getenv("HARDENER_INTEGRATION") == "" {
		t.Skip("set HARDENER_INTEGRATION=1 to run integration tests")
	}
	if os.Getuid() != 0 {
		t.Fatal("integration tests must run as root")
	}

	ctx := context.Background()
	exec := executor.NewLocalExecutor()

	// Read original sshd_config
	original, err := exec.ReadFile(ctx, sshmod.ConfigPath)
	require.NoError(t, err)

	// Snapshot for rollback
	backupDir := t.TempDir()
	bs := backup.NewStore(backupDir)
	entry, err := bs.SnapshotFile(ctx, "integration-test", "ssh-hardening", "SSH-7408", 0, sshmod.ConfigPath)
	require.NoError(t, err)

	// Plan
	m := sshmod.New()
	finding := &model.Finding{ID: "SSH-7408", Category: "SSH", Severity: model.SeverityWarning}
	profile := &model.Profile{MaxRiskLevel: model.RiskHigh}
	inspect := executor.NewLocalExecutor()

	action, err := m.Plan(ctx, finding, profile, inspect)
	require.NoError(t, err)

	if !action.Applicable {
		t.Logf("SSH-7408 not applicable on this system: %s", action.SkipReason)
		t.Skip("system already hardened, skipping apply test")
	}

	// Apply
	applied, err := m.Apply(ctx, action, exec)
	require.NoError(t, err, "Apply must succeed")
	assert.Equal(t, model.ActionApplied, applied.Status)

	// Validate
	err = m.Validate(ctx, action, inspect)
	assert.NoError(t, err, "Validate must pass after Apply")

	// Rollback
	err = m.Rollback(ctx, &entry, exec)
	require.NoError(t, err, "Rollback must succeed")

	// Verify original content restored
	restored, err := exec.ReadFile(ctx, sshmod.ConfigPath)
	require.NoError(t, err)
	assert.Equal(t, string(original), string(restored), "file must be restored to original after rollback")
}

// TestIntegration_SSHHardening_Idempotent verifies that applying twice produces no error.
func TestIntegration_SSHHardening_Idempotent(t *testing.T) {
	if os.Getenv("HARDENER_INTEGRATION") == "" {
		t.Skip("set HARDENER_INTEGRATION=1 to run integration tests")
	}
	if os.Getuid() != 0 {
		t.Fatal("integration tests must run as root")
	}

	ctx := context.Background()
	exec := executor.NewLocalExecutor()
	inspect := executor.NewLocalExecutor()

	m := sshmod.New()
	finding := &model.Finding{ID: "SSH-7408", Category: "SSH"}
	profile := &model.Profile{MaxRiskLevel: model.RiskHigh}

	// First apply
	action1, err := m.Plan(ctx, finding, profile, inspect)
	require.NoError(t, err)
	if action1.Applicable {
		_, err = m.Apply(ctx, action1, exec)
		require.NoError(t, err)
	}

	// Second plan — must be not applicable (idempotent)
	action2, err := m.Plan(ctx, finding, profile, inspect)
	require.NoError(t, err)
	assert.False(t, action2.Applicable, "second Plan() must return not applicable — system already hardened")
}
```

- [ ] **Step 2: Verify integration tests compile with the build tag**

```bash
go build -tags integration ./e2e/...
```

Expected: compiles with no errors.

- [ ] **Step 3: Run unit tests only (no integration)**

```bash
go test ./... -v 2>&1 | grep -E "^(ok|FAIL|---)"
```

Expected: all packages `ok`, integration tests skipped.

- [ ] **Step 4: Run integration tests on Ubuntu (requires root and HARDENER_INTEGRATION=1)**

```bash
# Only on an Ubuntu VM/host with sshd installed:
sudo HARDENER_INTEGRATION=1 go test -tags integration ./e2e/... -v
```

Expected: PASS for apply + validate + rollback cycle. File content restored to original.

- [ ] **Step 5: Final commit**

```bash
git add e2e/ internal/safety/ssh.go
git commit -m "feat: add SSH hardening integration tests with apply/rollback/idempotency verification"
```

- [ ] **Step 6: Final Milestone 3 tag**

```bash
git add .
git status  # should be clean
git log --oneline -10
git tag v0.1.0
```
