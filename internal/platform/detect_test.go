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
