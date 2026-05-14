package cmd

import (
	"github.com/maestroi/hardener/internal/model"
	"github.com/maestroi/hardener/internal/registry"
)

func filterFindings(
	findings []*model.Finding,
	reg *registry.Registry,
	findingIDs, moduleIDs []string,
) []*model.Finding {
	if len(findingIDs) == 0 && len(moduleIDs) == 0 {
		return findings
	}
	fSet := sliceToSet(findingIDs)
	mSet := sliceToSet(moduleIDs)
	out := make([]*model.Finding, 0, len(findings))
	for _, f := range findings {
		if len(findingIDs) > 0 && !fSet[f.ID] {
			continue
		}
		if len(moduleIDs) > 0 {
			mod, ok := reg.Lookup(f.ID)
			if !ok || !mSet[mod.Metadata().ID] {
				continue
			}
		}
		out = append(out, f)
	}
	return out
}

func sliceToSet(s []string) map[string]bool {
	m := make(map[string]bool, len(s))
	for _, x := range s {
		m[x] = true
	}
	return m
}
