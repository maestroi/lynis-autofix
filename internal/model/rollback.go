package model

import (
	"io/fs"
	"time"
)

// RollbackKind identifies what kind of system state a rollback entry covers.
type RollbackKind string

const (
	RollbackFile    RollbackKind = "file"
	RollbackSysctl  RollbackKind = "sysctl"
	RollbackService RollbackKind = "service"
	RollbackPackage RollbackKind = "package"
)

// RollbackEntry records the state of one system artifact before mutation.
// Rollback engine reverses entries in descending Index order.
type RollbackEntry struct {
	Index       int          `json:"index"`
	CreatedAt   time.Time    `json:"created_at"`
	Description string       `json:"description"`
	ModuleID    string       `json:"module_id"`
	FindingID   string       `json:"finding_id"`
	Kind        RollbackKind `json:"kind"`

	// File fields
	Path       string      `json:"path,omitempty"`
	BackupPath string      `json:"backup_path,omitempty"`
	OrigMode   fs.FileMode `json:"orig_mode,omitempty"`
	OrigUID    int         `json:"orig_uid,omitempty"`
	OrigGID    int         `json:"orig_gid,omitempty"`

	// Sysctl fields
	SysctlKey   string `json:"sysctl_key,omitempty"`
	SysctlValue string `json:"sysctl_value,omitempty"`

	// Service fields
	ServiceName string `json:"service_name,omitempty"`
	WasEnabled  bool   `json:"was_enabled,omitempty"`
	WasActive   bool   `json:"was_active,omitempty"`

	// Package fields
	PackageName  string `json:"package_name,omitempty"`
	WasInstalled bool   `json:"was_installed,omitempty"`
}

// RollbackManifest is the per-run record of all pre-mutation state snapshots.
type RollbackManifest struct {
	RunID     string          `json:"run_id"`
	CreatedAt time.Time       `json:"created_at"`
	Entries   []RollbackEntry `json:"entries"`
	Complete  bool            `json:"complete"`
}
