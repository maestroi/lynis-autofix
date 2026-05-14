package usbstorage_test

import (
	"context"
	"testing"

	"github.com/maestroi/hardener/internal/model"
	"github.com/maestroi/hardener/internal/modules/kernel/usbstorage"
	"github.com/maestroi/hardener/internal/testhelpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPlan_AlreadyBlacklisted(t *testing.T) {
	m := usbstorage.New()
	inspect := &testhelpers.FakeInspector{
		Files: map[string][]byte{usbstorage.ConfPath: []byte(usbstorage.ConfContent)},
	}
	action, err := m.Plan(context.Background(), &model.Finding{ID: "USB-1000"}, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.False(t, action.Applicable)
}

func TestPlan_NotPresent(t *testing.T) {
	m := usbstorage.New()
	inspect := &testhelpers.FakeInspector{}
	action, err := m.Plan(context.Background(), &model.Finding{ID: "HRDN-7230"}, &model.Profile{}, inspect)
	require.NoError(t, err)
	assert.True(t, action.Applicable)
}

func TestApplyAndValidate(t *testing.T) {
	m := usbstorage.New()
	exec := &testhelpers.FakeExecutor{}
	action := &model.PlannedAction{FindingID: "USB-1000", ModuleID: "kernel-usb-storage", Applicable: true}

	applied, err := m.Apply(context.Background(), action, exec)
	require.NoError(t, err)
	assert.Equal(t, model.ActionApplied, applied.Status)
	assert.True(t, exec.FileContains(usbstorage.ConfPath, "blacklist usb-storage"))

	err = m.Validate(context.Background(), action, exec)
	assert.NoError(t, err)
}
