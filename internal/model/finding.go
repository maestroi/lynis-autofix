package model

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Severity maps to Lynis finding types.
type Severity int

const (
	SeverityInfo Severity = iota // Lynis suggestion
	SeverityWarning              // Lynis warning
	SeverityCritical             // Reserved for future scanners
)

func (s Severity) String() string {
	switch s {
	case SeverityInfo:
		return "info"
	case SeverityWarning:
		return "warning"
	case SeverityCritical:
		return "critical"
	default:
		return "unknown"
	}
}

func (s Severity) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

func (s *Severity) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}
	switch strings.ToLower(str) {
	case "info":
		*s = SeverityInfo
	case "warning":
		*s = SeverityWarning
	case "critical":
		*s = SeverityCritical
	default:
		return fmt.Errorf("unknown severity: %q", str)
	}
	return nil
}

// Finding is the normalized representation of a single Lynis finding.
type Finding struct {
	ID          string   `json:"id"`
	Category    string   `json:"category"`
	Description string   `json:"description"`
	Severity    Severity `json:"severity"`
	Details     []string `json:"details,omitempty"`
	Source      string   `json:"source"` // "lynis" | "openscap" | "custom"
	Raw         string   `json:"raw,omitempty"`
}

// CategoryFromID derives a category from the finding ID prefix.
// "SSH-7408" → "SSH", "KRNL-6000" → "KRNL".
func CategoryFromID(id string) string {
	if id == "" {
		return "UNKNOWN"
	}
	parts := strings.SplitN(id, "-", 2)
	return parts[0]
}
