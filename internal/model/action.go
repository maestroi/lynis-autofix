package model

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// RiskLevel describes how risky a remediation action is.
type RiskLevel int

const (
	RiskNone RiskLevel = iota
	RiskLow             // config tweak, no service restart
	RiskMedium          // service restart or sysctl change
	RiskHigh            // firewall rule or kernel param
	RiskCritical        // requires --confirm-dangerous
)

func (r RiskLevel) String() string {
	switch r {
	case RiskNone:
		return "none"
	case RiskLow:
		return "low"
	case RiskMedium:
		return "medium"
	case RiskHigh:
		return "high"
	case RiskCritical:
		return "critical"
	default:
		return "unknown"
	}
}

func (r RiskLevel) MarshalJSON() ([]byte, error) {
	return json.Marshal(r.String())
}

func (r *RiskLevel) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}
	switch strings.ToLower(str) {
	case "none":
		*r = RiskNone
	case "low":
		*r = RiskLow
	case "medium":
		*r = RiskMedium
	case "high":
		*r = RiskHigh
	case "critical":
		*r = RiskCritical
	default:
		return fmt.Errorf("unknown risk level: %q", str)
	}
	return nil
}

func (r *RiskLevel) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err != nil {
		return err
	}
	switch strings.ToLower(s) {
	case "", "none":
		*r = RiskNone
	case "low":
		*r = RiskLow
	case "medium":
		*r = RiskMedium
	case "high":
		*r = RiskHigh
	case "critical":
		*r = RiskCritical
	default:
		return fmt.Errorf("unknown risk level: %q (valid: none, low, medium, high, critical)", s)
	}
	return nil
}

// ActionStatus records what happened to a planned action.
type ActionStatus string

const (
	ActionPlanned      ActionStatus = "planned"
	ActionSkipped      ActionStatus = "skipped"
	ActionApplied      ActionStatus = "applied"
	ActionFailed       ActionStatus = "failed"
	ActionRolledBack   ActionStatus = "rolled_back"
	ActionNotAttempted ActionStatus = "not_attempted"
)

// PlannedAction is the output of Module.Plan() — describes what would happen.
type PlannedAction struct {
	FindingID      string            `json:"finding_id"`
	ModuleID       string            `json:"module_id"`
	Title          string            `json:"title"`
	Description    string            `json:"description"`
	Steps          []string          `json:"steps,omitempty"`
	Metadata       map[string]string `json:"metadata,omitempty"`
	Risk           RiskLevel         `json:"risk"`
	Impact         string            `json:"impact,omitempty"`
	RequiresReboot bool              `json:"requires_reboot"`
	CanRollback    bool              `json:"can_rollback"`
	Dangerous      bool              `json:"dangerous"`
	Applicable     bool              `json:"applicable"`
	SkipReason     string            `json:"skip_reason,omitempty"`
	Tags           []string          `json:"tags,omitempty"`
}

// AppliedAction embeds the plan and adds execution outcome fields.
type AppliedAction struct {
	PlannedAction
	AppliedAt    time.Time    `json:"applied_at"`
	Status       ActionStatus `json:"status"`
	Error        string       `json:"error,omitempty"`
	RollbackKeys []string     `json:"rollback_keys,omitempty"`
}
