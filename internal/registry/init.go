package registry

// Default returns the production registry with all bundled modules registered.
// In Milestone 1, no concrete modules exist yet — returns an empty registry.
// Modules are added in Milestone 3.
func Default() *Registry {
	return New()
}
