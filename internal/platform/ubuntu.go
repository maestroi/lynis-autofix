package platform

import "strings"

// MajorVersion returns the major version number string, e.g. "22" from "22.04".
func (o OSInfo) MajorVersion() string {
	parts := strings.SplitN(o.Version, ".", 2)
	return parts[0]
}

// SupportsDistro returns true if the OS matches any of the given distro identifiers.
// Supported identifiers: "ubuntu", "ubuntu-22.04", "ubuntu-24.04".
func (o OSInfo) SupportsDistro(supported []string) bool {
	for _, s := range supported {
		parts := strings.SplitN(s, "-", 2)
		if !strings.EqualFold(parts[0], o.Name) {
			continue
		}
		if len(parts) == 1 {
			return true // "ubuntu" matches any ubuntu version
		}
		if parts[1] == o.Version {
			return true // "ubuntu-22.04" matches exactly
		}
	}
	return false
}
