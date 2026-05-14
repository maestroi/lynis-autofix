package ssh

import (
	"fmt"
	"regexp"
	"strings"
)

// ConfigPath is the canonical path to the sshd configuration file on Ubuntu.
const ConfigPath = "/etc/ssh/sshd_config"

// directive represents a required sshd_config directive and its target value.
type directive struct {
	key              string
	value            string
	humanDescription string
}

// requiredDirectives returns the directives needed to remediate a specific finding.
func requiredDirectives(findingID string) []directive {
	switch findingID {
	case "SSH-7408":
		return []directive{
			{"PermitRootLogin", "no", "Set PermitRootLogin no — disallow direct root SSH login"},
			{"LoginGraceTime", "60", "Set LoginGraceTime 60 — reduce authentication window"},
			{"MaxAuthTries", "4", "Set MaxAuthTries 4 — limit brute-force attempts"},
			{"X11Forwarding", "no", "Set X11Forwarding no — disable unnecessary X11 forwarding"},
		}
	case "SSH-7902":
		return []directive{
			{"Protocol", "2", "Set Protocol 2 — enforce SSHv2 only"},
		}
	default:
		return nil
	}
}

// missingOrWrongDirectives returns only the directives that are absent or set to the wrong value.
func missingOrWrongDirectives(config string, directives []directive) []directive {
	var needed []directive
	for _, d := range directives {
		if !directiveMatches(config, d.key, d.value) {
			needed = append(needed, d)
		}
	}
	return needed
}

// directiveMatches returns true if key=value is present as an active (uncommented) line.
func directiveMatches(config, key, value string) bool {
	re := regexp.MustCompile(`(?im)^\s*` + regexp.QuoteMeta(key) + `\s+` + regexp.QuoteMeta(value) + `\s*$`)
	return re.MatchString(config)
}

// applyDirectives sets or replaces directives in config text.
// Existing active lines are replaced in-place. Missing directives are appended.
func applyDirectives(config string, directives []directive) string {
	lines := strings.Split(config, "\n")
	applied := make(map[string]bool)

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		parts := strings.Fields(trimmed)
		if len(parts) < 2 {
			continue
		}
		key := parts[0]
		for _, d := range directives {
			if strings.EqualFold(key, d.key) {
				lines[i] = fmt.Sprintf("%s %s", d.key, d.value)
				applied[d.key] = true
				break
			}
		}
	}

	var appended []string
	for _, d := range directives {
		if !applied[d.key] {
			appended = append(appended, fmt.Sprintf("%s %s", d.key, d.value))
		}
	}

	result := strings.Join(lines, "\n")
	if len(appended) > 0 {
		result += "\n# Added by hardener\n" + strings.Join(appended, "\n") + "\n"
	}
	return result
}
