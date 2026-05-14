package registry_test

import (
	"context"
	"testing"

	"github.com/maestroi/hardener/internal/executor"
	"github.com/maestroi/hardener/internal/model"
	"github.com/maestroi/hardener/internal/modules"
	"github.com/maestroi/hardener/internal/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubModule is a minimal Module implementation for testing.
type stubModule struct {
	meta     modules.ModuleMetadata
	findings []string
}

func (s *stubModule) Metadata() modules.ModuleMetadata { return s.meta }
func (s *stubModule) SupportedFindings() []string      { return s.findings }
func (s *stubModule) Plan(_ context.Context, _ *model.Finding, _ *model.Profile, _ executor.Inspector) (*model.PlannedAction, error) {
	return &model.PlannedAction{Applicable: true}, nil
}
func (s *stubModule) Apply(_ context.Context, _ *model.PlannedAction, _ executor.Executor) (*model.AppliedAction, error) {
	return &model.AppliedAction{}, nil
}
func (s *stubModule) Validate(_ context.Context, _ *model.PlannedAction, _ executor.Inspector) error {
	return nil
}
func (s *stubModule) Rollback(_ context.Context, _ *model.RollbackEntry, _ executor.Executor) error {
	return nil
}

func TestRegistry_LookupMiss(t *testing.T) {
	r := registry.New()
	_, ok := r.Lookup("UNKNOWN-0000")
	assert.False(t, ok)
}

func TestRegistry_RegisterAndLookupByFinding(t *testing.T) {
	r := registry.New()
	m := &stubModule{
		meta:     modules.ModuleMetadata{ID: "ssh-hardening"},
		findings: []string{"SSH-7408", "SSH-7902"},
	}
	r.Register(m)

	got, ok := r.Lookup("SSH-7408")
	require.True(t, ok)
	assert.Equal(t, "ssh-hardening", got.Metadata().ID)

	got2, ok2 := r.Lookup("SSH-7902")
	require.True(t, ok2)
	assert.Equal(t, "ssh-hardening", got2.Metadata().ID)
}

func TestRegistry_LookupByModuleID(t *testing.T) {
	r := registry.New()
	m := &stubModule{
		meta:     modules.ModuleMetadata{ID: "ssh-hardening"},
		findings: []string{"SSH-7408"},
	}
	r.Register(m)

	got, ok := r.LookupByModuleID("ssh-hardening")
	require.True(t, ok)
	assert.Equal(t, "ssh-hardening", got.Metadata().ID)

	_, ok2 := r.LookupByModuleID("does-not-exist")
	assert.False(t, ok2)
}

func TestRegistry_All_NoDuplicates(t *testing.T) {
	r := registry.New()
	m := &stubModule{
		meta:     modules.ModuleMetadata{ID: "ssh-hardening"},
		findings: []string{"SSH-7408", "SSH-7902"},
	}
	r.Register(m)
	all := r.All()
	assert.Len(t, all, 1) // one module, two findings — All() returns distinct modules
}

func TestRegistry_Default_HasBundledModules(t *testing.T) {
	r := registry.Default()
	all := r.All()
	require.NotEmpty(t, all)
	_, ok := r.Lookup("SSH-7408")
	assert.True(t, ok)
}

func TestRegistry_Default_ContainsGroup1Modules(t *testing.T) {
	r := registry.Default()
	findingIDs := []string{
		"PKGS-7394",
		"PKGS-7370",
		"BANN-7126",
		"BANN-7130",
		"LOGG-2154",
		"ACCT-9622",
		"ACCT-9626",
	}
	for _, id := range findingIDs {
		mod, ok := r.Lookup(id)
		assert.True(t, ok, "finding %s should have a registered module", id)
		assert.NotNil(t, mod, "module for %s must not be nil", id)
	}
}

func TestRegistry_Default_ContainsModulesForCurrentSkippedFindings(t *testing.T) {
	r := registry.Default()
	findingIDs := []string{
		"DEB-0280",
		"DEB-0810",
		"DEB-0811",
		"DEB-0880",
		"BOOT-5122",
		"BOOT-5264",
		"KRNL-5830",
		"FILE-6310",
		"USB-1000",
		"NAME-4028",
		"NETW-3200",
		"FIRE-4513",
		"LOGG-2190",
		"ACCT-9628",
		"FINT-4350",
		"TOOL-5002",
		"FILE-7524",
		"HRDN-7222",
		"HRDN-7230",
	}
	for _, id := range findingIDs {
		mod, ok := r.Lookup(id)
		assert.True(t, ok, "finding %s should have a registered module", id)
		assert.NotNil(t, mod, "module for %s must not be nil", id)
	}
}
