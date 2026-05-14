package homemount_test

import (
	"context"
	"strings"
	"testing"

	"github.com/maestroi/hardener/internal/model"
	"github.com/maestroi/hardener/internal/modules/filesystem/homemount"
	"github.com/maestroi/hardener/internal/testhelpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const fstabHomeSecure = `# /etc/fstab
UUID=abc / ext4 defaults 0 1
UUID=def /home ext4 defaults,nodev 0 2
`

const fstabHomeNeedsFixing = `# /etc/fstab
UUID=abc / ext4 defaults 0 1
UUID=def /home ext4 defaults 0 2
`

const fstabNoHomeEntry = `# /etc/fstab
UUID=abc / ext4 defaults 0 1
`

func TestPlan_AlreadySecure(t *testing.T) {
	m := homemount.New()
	inspect := &testhelpers.FakeInspector{
		Files: map[string][]byte{homemount.FstabPath: []byte(fstabHomeSecure)},
	}
	action, err := m.Plan(context.Background(), &model.Finding{ID: "FILE-7524"}, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.False(t, action.Applicable)
}

func TestPlan_NeedsNodev(t *testing.T) {
	m := homemount.New()
	inspect := &testhelpers.FakeInspector{
		Files: map[string][]byte{homemount.FstabPath: []byte(fstabHomeNeedsFixing)},
	}
	action, err := m.Plan(context.Background(), &model.Finding{ID: "FILE-7524"}, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.True(t, action.Applicable)
	assert.True(t, action.Dangerous)
	assert.Equal(t, model.RiskHigh, action.Risk)
}

func TestPlan_NoHomeEntry_Skips(t *testing.T) {
	m := homemount.New()
	inspect := &testhelpers.FakeInspector{
		Files: map[string][]byte{homemount.FstabPath: []byte(fstabNoHomeEntry)},
	}
	action, err := m.Plan(context.Background(), &model.Finding{ID: "FILE-7524"}, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.False(t, action.Applicable)
	assert.Contains(t, action.SkipReason, "no /home entry")
}

func TestApplyAndValidate(t *testing.T) {
	m := homemount.New()
	exec := &testhelpers.FakeExecutor{
		FakeInspector: testhelpers.FakeInspector{
			Files: map[string][]byte{homemount.FstabPath: []byte(fstabHomeNeedsFixing)},
		},
	}
	action := &model.PlannedAction{
		FindingID:  "FILE-7524",
		ModuleID:   "filesystem-homemount",
		Applicable: true,
		Dangerous:  true,
	}

	applied, err := m.Apply(context.Background(), action, exec)
	require.NoError(t, err)
	assert.Equal(t, model.ActionApplied, applied.Status)
	assert.True(t, strings.Contains(string(exec.WrittenFiles[homemount.FstabPath]), "nodev"))

	err = m.Validate(context.Background(), action, exec)
	assert.NoError(t, err)
}
