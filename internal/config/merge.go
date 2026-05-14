package config

import "github.com/maestroi/hardener/internal/model"

// ApplyOverrides merges ProfileOverrides onto a Profile copy.
// Lists are appended and deduplicated; scalars are not overridden by overlays.
func ApplyOverrides(base *model.Profile, overrides ProfileOverrides) *model.Profile {
	result := *base // shallow copy
	result.AllowedModules = mergeStringSlice(base.AllowedModules, overrides.AllowedModules)
	result.BlockedModules = mergeStringSlice(base.BlockedModules, overrides.BlockedModules)
	result.ProtectedProcesses = mergeStringSlice(base.ProtectedProcesses, overrides.ProtectedProcesses)
	result.ProtectedServices = mergeStringSlice(base.ProtectedServices, overrides.ProtectedServices)
	result.ProtectedPorts = mergeIntSlice(base.ProtectedPorts, overrides.ProtectedPorts)
	result.ProtectedPortRanges = append(append([]model.PortRange{}, base.ProtectedPortRanges...), overrides.ProtectedPortRanges...)
	return &result
}

func mergeStringSlice(base, overlay []string) []string {
	seen := make(map[string]struct{}, len(base)+len(overlay))
	result := make([]string, 0, len(base)+len(overlay))
	for _, s := range append(base, overlay...) {
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			result = append(result, s)
		}
	}
	return result
}

func mergeIntSlice(base, overlay []int) []int {
	seen := make(map[int]struct{}, len(base)+len(overlay))
	result := make([]int, 0, len(base)+len(overlay))
	for _, v := range append(base, overlay...) {
		if _, ok := seen[v]; !ok {
			seen[v] = struct{}{}
			result = append(result, v)
		}
	}
	return result
}
