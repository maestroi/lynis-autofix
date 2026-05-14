package tmpmount_test

import (
	"context"
	"strings"
	"testing"

	"github.com/maestroi/hardener/internal/model"
	"github.com/maestroi/hardener/internal/modules/filesystem/tmpmount"
	"github.com/maestroi/hardener/internal/testhelpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const fstabAlreadySecure = `# /etc/fstab
UUID=abc / ext4 defaults 0 1
tmpfs /tmp tmpfs defaults,nodev,nosuid,noexec 0 0
`

const fstabNeedsFixing = `# /etc/fstab
UUID=abc / ext4 defaults 0 1
tmpfs /tmp tmpfs defaults 0 0
`

const fstabNoTmpEntry = `# /etc/fstab
UUID=abc / ext4 defaults 0 1
`

func TestPlan_AlreadySecure(t *testing.T) {
	m := tmpmount.New()
	inspect := &testhelpers.FakeInspector{
		Files: map[string][]byte{tmpmount.FstabPath: []byte(fstabAlreadySecure)},
	}
	action, err := m.Plan(context.Background(), &model.Finding{ID: "FILE-6310"}, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.False(t, action.Applicable)
}

func TestPlan_NeedsOptions(t *testing.T) {
	m := tmpmount.New()
	inspect := &testhelpers.FakeInspector{
		Files: map[string][]byte{tmpmount.FstabPath: []byte(fstabNeedsFixing)},
	}
	action, err := m.Plan(context.Background(), &model.Finding{ID: "FILE-6310"}, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.True(t, action.Applicable)
	assert.True(t, action.Dangerous)
	assert.Equal(t, model.RiskHigh, action.Risk)
}

func TestPlan_NoTmpEntry_AddsNew(t *testing.T) {
	m := tmpmount.New()
	inspect := &testhelpers.FakeInspector{
		Files: map[string][]byte{tmpmount.FstabPath: []byte(fstabNoTmpEntry)},
	}
	action, err := m.Plan(context.Background(), &model.Finding{ID: "FILE-6310"}, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.True(t, action.Applicable)
	assert.True(t, action.Dangerous)
}

func TestApplyAndValidate(t *testing.T) {
	m := tmpmount.New()
	exec := &testhelpers.FakeExecutor{
		FakeInspector: testhelpers.FakeInspector{
			Files: map[string][]byte{tmpmount.FstabPath: []byte(fstabNeedsFixing)},
		},
	}
	action := &model.PlannedAction{
		FindingID:  "FILE-6310",
		ModuleID:   "filesystem-tmpmount",
		Applicable: true,
		Dangerous:  true,
	}

	applied, err := m.Apply(context.Background(), action, exec)
	require.NoError(t, err)
	assert.Equal(t, model.ActionApplied, applied.Status)

	written := string(exec.WrittenFiles[tmpmount.FstabPath])
	assert.True(t, strings.Contains(written, "nodev"))
	assert.True(t, strings.Contains(written, "nosuid"))
	assert.True(t, strings.Contains(written, "noexec"))

	err = m.Validate(context.Background(), action, exec)
	assert.NoError(t, err)
}
