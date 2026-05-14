package model

import "time"

// ScanResult stores the output of a single Lynis scan.
// Persisted to <stateDir>/scans/<timestamp>.json.
type ScanResult struct {
	Timestamp  time.Time  `json:"timestamp"`
	ReportPath string     `json:"report_path"`
	Score      int        `json:"score"`
	Findings   []*Finding `json:"findings"`
}
