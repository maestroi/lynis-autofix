package grubpassword_test

import (
	"context"
	"testing"

	"github.com/maestroi/hardener/internal/executor"
	"github.com/maestroi/hardener/internal/model"
	"github.com/maestroi/hardener/internal/modules/boot/grubpassword"
	"github.com/maestroi/hardener/internal/testhelpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testHash = "grub.pbkdf2.sha512.10000.AABBCC.DDEEFF"

func TestPlan_NoHashInProfile(t *testing.T) {
	m := grubpassword.New()
	inspect := &testhelpers.FakeInspector{}
	action, err := m.Plan(context.Background(), &model.Finding{ID: "BOOT-5122"}, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.False(t, action.Applicable)
	assert.Contains(t, action.SkipReason, "grub_password_hash")
}

func TestPlan_AlreadyConfigured(t *testing.T) {
	m := grubpassword.New()
	profile := &model.Profile{GrubPasswordHash: testHash}
	inspect := &testhelpers.FakeInspector{
		Files: map[string][]byte{
			grubpassword.ScriptPath: []byte("password_pbkdf2 root " + testHash),
		},
	}
	action, err := m.Plan(context.Background(), &model.Finding{ID: "BOOT-5122"}, profile, inspect)
	require.NoError(t, err)
	assert.False(t, action.Applicable)
}

func TestPlan_NeedsPassword(t *testing.T) {
	m := grubpassword.New()
	profile := &model.Profile{GrubPasswordHash: testHash}
	inspect := &testhelpers.FakeInspector{}
	action, err := m.Plan(context.Background(), &model.Finding{ID: "BOOT-5122"}, profile, inspect)
	require.NoError(t, err)
	assert.True(t, action.Applicable)
	assert.True(t, action.Dangerous)
	assert.Equal(t, model.RiskCritical, action.Risk)
}

func TestApplyAndValidate(t *testing.T) {
	m := grubpassword.New()
	exec := &testhelpers.FakeExecutor{
		RunFn: func(name string, args ...string) (executor.CmdOutput, error) {
			return executor.CmdOutput{}, nil
		},
	}
	action := &model.PlannedAction{
		FindingID:  "BOOT-5122",
		ModuleID:   "boot-grub-password",
		Applicable: true,
		Dangerous:  true,
		Metadata:   map[string]string{"hash": testHash},
	}

	applied, err := m.Apply(context.Background(), action, exec)
	require.NoError(t, err)
	assert.Equal(t, model.ActionApplied, applied.Status)
	assert.True(t, exec.FileContains(grubpassword.ScriptPath, testHash))

	err = m.Validate(context.Background(), action, exec)
	assert.NoError(t, err)
}
