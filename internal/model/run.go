package model

import "time"

// RunStatus tracks the lifecycle of an apply run.
type RunStatus string

const (
	RunPlanning   RunStatus = "planning"
	RunApplying   RunStatus = "applying"
	RunCompleted  RunStatus = "completed"
	RunFailed     RunStatus = "failed"
	RunRolledBack RunStatus = "rolled_back"
)

// Run is the index record for a single apply execution.
// Full detail lives in plan.json, applied.json, rollback.json inside the run directory.
type Run struct {
	ID            string     `json:"id"`
	StartedAt     time.Time  `json:"started_at"`
	FinishedAt    *time.Time `json:"finished_at,omitempty"`
	ProfileName   string     `json:"profile_name"`
	ScannerSource string     `json:"scanner_source"`
	StateDir      string     `json:"state_dir"`
	DryRun        bool       `json:"dry_run"`
	Status        RunStatus  `json:"status"`
	ScoreBefore   int        `json:"score_before"`
	ScoreAfter    int        `json:"score_after,omitempty"`
	OSName        string     `json:"os_name,omitempty"`
	OSVersion     string     `json:"os_version,omitempty"`
	KernelVersion string     `json:"kernel_version,omitempty"`
	Hostname      string     `json:"hostname,omitempty"`
}
