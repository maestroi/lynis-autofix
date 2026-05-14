package model_test

import (
	"testing"

	"github.com/maestroi/hardener/internal/model"
	"github.com/stretchr/testify/assert"
)

func TestProfile_IsModuleBlocked(t *testing.T) {
	p := model.Profile{BlockedModules: []string{"firewall-baseline", "auditd-basic"}}
	assert.True(t, p.IsModuleBlocked("firewall-baseline"))
	assert.True(t, p.IsModuleBlocked("auditd-basic"))
	assert.False(t, p.IsModuleBlocked("ssh-hardening"))
}

func TestProfile_IsModuleAllowed_EmptyListAllowsAll(t *testing.T) {
	p := model.Profile{AllowedModules: []string{}}
	assert.True(t, p.IsModuleAllowed("anything"))
}

func TestProfile_IsModuleAllowed_RestrictedList(t *testing.T) {
	p := model.Profile{AllowedModules: []string{"ssh-hardening"}}
	assert.True(t, p.IsModuleAllowed("ssh-hardening"))
	assert.False(t, p.IsModuleAllowed("auditd-basic"))
}

func TestProfile_IsPortProtected_DirectPort(t *testing.T) {
	p := model.Profile{ProtectedPorts: []int{22, 80}}
	assert.True(t, p.IsPortProtected(22, "tcp"))
	assert.True(t, p.IsPortProtected(80, "tcp"))
	assert.False(t, p.IsPortProtected(443, "tcp"))
}

func TestProfile_IsPortProtected_Range(t *testing.T) {
	p := model.Profile{
		ProtectedPortRanges: []model.PortRange{
			{Start: 9000, End: 9001, Proto: "tcp"},
		},
	}
	assert.True(t, p.IsPortProtected(9000, "tcp"))
	assert.True(t, p.IsPortProtected(9001, "tcp"))
	assert.False(t, p.IsPortProtected(9002, "tcp"))
	assert.False(t, p.IsPortProtected(9000, "udp")) // proto mismatch
}

func TestProfile_IsPortProtected_Range_BothProto(t *testing.T) {
	p := model.Profile{
		ProtectedPortRanges: []model.PortRange{
			{Start: 30303, End: 30303, Proto: "both"},
		},
	}
	assert.True(t, p.IsPortProtected(30303, "tcp"))
	assert.True(t, p.IsPortProtected(30303, "udp"))
}

func TestProfile_IsServiceProtected(t *testing.T) {
	p := model.Profile{ProtectedServices: []string{"docker", "containerd"}}
	assert.True(t, p.IsServiceProtected("docker"))
	assert.False(t, p.IsServiceProtected("ssh"))
}

func TestProfile_IsProcessProtected(t *testing.T) {
	p := model.Profile{ProtectedProcesses: []string{"lighthouse", "geth"}}
	assert.True(t, p.IsProcessProtected("lighthouse"))
	assert.False(t, p.IsProcessProtected("sshd"))
}
