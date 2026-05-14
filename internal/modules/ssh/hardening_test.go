package ssh_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
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

	fakeExec := &fakeExecutor{
		fakeInspector: fakeInspector{files: map[string][]byte{sshmod.ConfigPath: content}},
		configPath:    configPath,
		sshdTValid:    true,
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
		fakeInspector: fakeInspector{files: map[string][]byte{sshmod.ConfigPath: content}},
		sshdTValid:    false,
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
	backupContent := []byte("PermitRootLogin yes\n")
	require.NoError(t, os.WriteFile(backupPath, backupContent, 0600))

	fakeExec := &fakeExecutor{
		fakeInspector: fakeInspector{
			files: map[string][]byte{
				backupPath: backupContent,
			},
		},
		sshdTValid: true,
	}

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

func (f *fakeExecutor) ReadFile(ctx context.Context, path string) ([]byte, error) {
	if f.files != nil {
		if data, ok := f.files[path]; ok {
			return data, nil
		}
	}
	return f.fakeInspector.ReadFile(ctx, path)
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
func (f *fakeExecutor) SetSysctl(_ context.Context, key, value string) error        { return nil }
func (f *fakeExecutor) EnableService(_ context.Context, name string) error          { return nil }
func (f *fakeExecutor) DisableService(_ context.Context, name string) error         { return nil }
func (f *fakeExecutor) StartService(_ context.Context, name string) error           { return nil }
func (f *fakeExecutor) StopService(_ context.Context, name string) error            { return nil }
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
