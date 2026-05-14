package config_test

import (
	"testing"

	"github.com/maestroi/hardener/internal/config"
	"github.com/maestroi/hardener/internal/model"
	"github.com/stretchr/testify/assert"
)

func TestApplyOverrides_AppendsDeduplicated(t *testing.T) {
	base := &model.Profile{
		ProtectedPorts: []int{22},
		BlockedModules: []string{"firewall-baseline"},
	}
	overrides := config.ProfileOverrides{
		ProtectedPorts: []int{22, 8080}, // 22 is a duplicate
		BlockedModules: []string{"auditd-basic"},
	}
	result := config.ApplyOverrides(base, overrides)
	assert.Equal(t, []int{22, 8080}, result.ProtectedPorts)
	assert.Equal(t, []string{"firewall-baseline", "auditd-basic"}, result.BlockedModules)
}

func TestApplyOverrides_DoesNotMutateBase(t *testing.T) {
	base := &model.Profile{ProtectedPorts: []int{22}}
	config.ApplyOverrides(base, config.ProfileOverrides{ProtectedPorts: []int{80}})
	assert.Equal(t, []int{22}, base.ProtectedPorts)
}
