package grubperms_test

import (
	"context"
	"os"
	"testing"

	"github.com/maestroi/hardener/internal/executor"
	"github.com/maestroi/hardener/internal/model"
	"github.com/maestroi/hardener/internal/modules/boot/grubperms"
	"github.com/maestroi/hardener/internal/testhelpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPlan_AlreadySecure(t *testing.T) {
	m := grubperms.New()
	inspect := &testhelpers.FakeInspector{
		Files: map[string][]byte{grubperms.GrubCfgPath: []byte("set default=0")},
		RunReadOnlyFn: func(name string, args ...string) (executor.CmdOutput, error) {
			return executor.CmdOutput{Stdout: "600\n"}, nil
		},
	}
	action, err := m.Plan(context.Background(), &model.Finding{ID: "BOOT-5264"}, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.False(t, action.Applicable)
}

func TestPlan_InsecurePerms(t *testing.T) {
	m := grubperms.New()
	inspect := &testhelpers.FakeInspector{
		Files: map[string][]byte{grubperms.GrubCfgPath: []byte("set default=0")},
		RunReadOnlyFn: func(name string, args ...string) (executor.CmdOutput, error) {
			return executor.CmdOutput{Stdout: "644\n"}, nil
		},
	}
	action, err := m.Plan(context.Background(), &model.Finding{ID: "BOOT-5264"}, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.True(t, action.Applicable)
}

func TestApplyAndValidate(t *testing.T) {
	m := grubperms.New()
	exec := &testhelpers.FakeExecutor{
		FakeInspector: testhelpers.FakeInspector{
			Files: map[string][]byte{grubperms.GrubCfgPath: []byte("set default=0")},
			RunReadOnlyFn: func(name string, args ...string) (executor.CmdOutput, error) {
				return executor.CmdOutput{Stdout: "600\n"}, nil
			},
		},
	}
	action := &model.PlannedAction{FindingID: "BOOT-5264", ModuleID: "boot-grub-perms", Applicable: true}

	applied, err := m.Apply(context.Background(), action, exec)
	require.NoError(t, err)
	assert.Equal(t, model.ActionApplied, applied.Status)
	assert.Equal(t, os.FileMode(0600), exec.SetFileModeRecords[grubperms.GrubCfgPath])

	err = m.Validate(context.Background(), action, exec)
	assert.NoError(t, err)
}
