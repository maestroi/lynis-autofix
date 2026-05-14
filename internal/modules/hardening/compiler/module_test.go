package compiler_test

import (
	"context"
	"testing"

	"github.com/maestroi/hardener/internal/executor"
	"github.com/maestroi/hardener/internal/model"
	"github.com/maestroi/hardener/internal/modules/hardening/compiler"
	"github.com/maestroi/hardener/internal/testhelpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func noneFound(name string, args ...string) (executor.CmdOutput, error) {
	return executor.CmdOutput{ExitCode: 1}, nil
}

func compilerFoundWith755(name string, args ...string) (executor.CmdOutput, error) {
	if name == "which" {
		return executor.CmdOutput{Stdout: "/usr/bin/" + args[0] + "\n", ExitCode: 0}, nil
	}
	return executor.CmdOutput{Stdout: "755\n", ExitCode: 0}, nil
}

func TestPlan_NoCompilersInstalled(t *testing.T) {
	m := compiler.New()
	inspect := &testhelpers.FakeInspector{RunReadOnlyFn: noneFound}
	action, err := m.Plan(context.Background(), &model.Finding{ID: "HRDN-7222"}, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.False(t, action.Applicable)
	assert.NotEmpty(t, action.SkipReason)
}

func TestPlan_CompilersNeedRestricting(t *testing.T) {
	m := compiler.New()
	inspect := &testhelpers.FakeInspector{RunReadOnlyFn: compilerFoundWith755}
	action, err := m.Plan(context.Background(), &model.Finding{ID: "HRDN-7222"}, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.True(t, action.Applicable)
	assert.Equal(t, model.RiskMedium, action.Risk)
	assert.Contains(t, action.Metadata["targets"], "/usr/bin/gcc")
}

func TestApplyAndValidate(t *testing.T) {
	m := compiler.New()
	exec := &testhelpers.FakeExecutor{
		FakeInspector: testhelpers.FakeInspector{
			RunReadOnlyFn: compilerFoundWith755,
		},
	}
	action := &model.PlannedAction{
		FindingID:  "HRDN-7222",
		ModuleID:   "hardening-compiler",
		Applicable: true,
		Metadata:   map[string]string{"targets": "/usr/bin/gcc,/usr/bin/g++"},
	}

	applied, err := m.Apply(context.Background(), action, exec)
	require.NoError(t, err)
	assert.Equal(t, model.ActionApplied, applied.Status)
	assert.NotNil(t, exec.SetFileModeRecords)
}
