package testhelpers_test

import (
	"context"
	"testing"

	"github.com/maestroi/hardener/internal/executor"
	"github.com/maestroi/hardener/internal/testhelpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Compile-time checks that both fakes implement the relevant interfaces.
var _ executor.Inspector = (*testhelpers.FakeInspector)(nil)
var _ executor.Executor = (*testhelpers.FakeExecutor)(nil)

func TestFakeExecutor_TracksInstallPackage(t *testing.T) {
	exec := &testhelpers.FakeExecutor{
		FakeInspector: testhelpers.FakeInspector{
			InstalledPkgs: map[string]bool{},
		},
	}

	require.NoError(t, exec.InstallPackage(context.Background(), "debsums"))
	assert.True(t, exec.PackageInstalled("debsums"))

	ok, err := exec.IsPackageInstalled(context.Background(), "debsums")
	require.NoError(t, err)
	assert.True(t, ok, "InstalledPkgs must be updated after InstallPackage")
}

func TestFakeExecutor_TracksServiceLifecycle(t *testing.T) {
	exec := &testhelpers.FakeExecutor{}

	require.NoError(t, exec.EnableService(context.Background(), "auditd"))
	require.NoError(t, exec.StartService(context.Background(), "auditd"))

	assert.True(t, testhelpers.ContainsService(exec.EnabledServices, "auditd"))
	assert.True(t, testhelpers.ContainsService(exec.StartedServices, "auditd"))

	state, err := exec.ServiceState(context.Background(), "auditd")
	require.NoError(t, err)
	assert.True(t, state.Active)
	assert.True(t, state.Enabled)
}

func TestFakeExecutor_WriteReadRoundTrip(t *testing.T) {
	exec := &testhelpers.FakeExecutor{}
	require.NoError(t, exec.WriteFile(context.Background(), "/etc/issue", []byte("banner text"), 0644))
	assert.True(t, exec.FileContains("/etc/issue", "banner"))
	assert.True(t, exec.HasWritten("/etc/issue"))
}
