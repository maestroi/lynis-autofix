package embedfs

import "embed"

// Profiles is the embedded filesystem containing bundled YAML profile files.
//
//go:embed profiles
var Profiles embed.FS
