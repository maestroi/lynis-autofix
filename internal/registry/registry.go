package registry

import "github.com/maestroi/hardener/internal/modules"

// Registry maps finding IDs and module IDs to Module implementations.
type Registry struct {
	byFinding map[string]modules.Module
	byModule  map[string]modules.Module
}

// New returns an empty Registry.
func New() *Registry {
	return &Registry{
		byFinding: make(map[string]modules.Module),
		byModule:  make(map[string]modules.Module),
	}
}

// Register adds a module to the registry, indexing it by all its supported finding IDs.
func (r *Registry) Register(m modules.Module) {
	r.byModule[m.Metadata().ID] = m
	for _, id := range m.SupportedFindings() {
		r.byFinding[id] = m
	}
}

// Lookup returns the module registered for a given finding ID.
func (r *Registry) Lookup(findingID string) (modules.Module, bool) {
	m, ok := r.byFinding[findingID]
	return m, ok
}

// LookupByModuleID returns a module by its module ID.
func (r *Registry) LookupByModuleID(moduleID string) (modules.Module, bool) {
	m, ok := r.byModule[moduleID]
	return m, ok
}

// All returns all registered modules without duplicates.
func (r *Registry) All() []modules.Module {
	seen := make(map[string]bool, len(r.byModule))
	result := make([]modules.Module, 0, len(r.byModule))
	for _, m := range r.byFinding {
		id := m.Metadata().ID
		if !seen[id] {
			seen[id] = true
			result = append(result, m)
		}
	}
	return result
}
