package model

// FailurePolicy controls what happens when a module's Apply fails.
type FailurePolicy string

const (
	FailureRollbackAndStop     FailurePolicy = "rollback_failed_and_stop"
	FailureRollbackAndContinue FailurePolicy = "rollback_failed_and_continue"
	FailureRollbackEntireRun   FailurePolicy = "rollback_entire_run"
	FailureStopWithoutRollback FailurePolicy = "stop_without_rollback"
)

// PortRange defines an inclusive port range with an optional protocol constraint.
type PortRange struct {
	Start int    `yaml:"start" json:"start"`
	End   int    `yaml:"end"   json:"end"`
	Proto string `yaml:"proto" json:"proto"` // "tcp" | "udp" | "both"
}

// SysctlPolicy controls which kernel parameters hardener may modify.
type SysctlPolicy struct {
	AllowNetworkChanges bool     `yaml:"allow_network_changes" json:"allow_network_changes"`
	AllowKernelChanges  bool     `yaml:"allow_kernel_changes"  json:"allow_kernel_changes"`
	BlockedKeys         []string `yaml:"blocked_keys"          json:"blocked_keys,omitempty"`
}

// Profile is the policy document that controls what hardener may do on this system.
type Profile struct {
	Name                string        `yaml:"name"                  json:"name"`
	Description         string        `yaml:"description"           json:"description"`
	AllowedModules      []string      `yaml:"allowed_modules"       json:"allowed_modules,omitempty"`
	BlockedModules      []string      `yaml:"blocked_modules"       json:"blocked_modules,omitempty"`
	ProtectedPorts      []int         `yaml:"protected_ports"       json:"protected_ports,omitempty"`
	ProtectedPortRanges []PortRange   `yaml:"protected_port_ranges" json:"protected_port_ranges,omitempty"`
	ProtectedProcesses  []string      `yaml:"protected_processes"   json:"protected_processes,omitempty"`
	ProtectedServices   []string      `yaml:"protected_services"    json:"protected_services,omitempty"`
	MaxRiskLevel        RiskLevel     `yaml:"max_risk_level"        json:"max_risk_level"`
	RequireConfirm      []string      `yaml:"require_confirm"       json:"require_confirm,omitempty"`
	SysctlPolicy        SysctlPolicy  `yaml:"sysctl_policy"         json:"sysctl_policy"`
	FailurePolicy       FailurePolicy `yaml:"failure_policy"        json:"failure_policy"`
	// RemoteSyslogServer is the host:port (e.g. "10.0.0.1:514") for remote syslog.
	// Required for LOGG-2190 remediation. Leave empty to skip.
	RemoteSyslogServer string `yaml:"remote_syslog_server" json:"remote_syslog_server"`
	// GrubPasswordHash is the grub2-mkpasswd-pbkdf2 hash for BOOT-5122 remediation.
	// Leave empty to skip. Generate with: grub-mkpasswd-pbkdf2
	GrubPasswordHash string `yaml:"grub_password_hash" json:"grub_password_hash"`
}

// IsModuleBlocked returns true if the module ID appears in BlockedModules.
func (p *Profile) IsModuleBlocked(moduleID string) bool {
	for _, id := range p.BlockedModules {
		if id == moduleID {
			return true
		}
	}
	return false
}

// IsModuleAllowed returns true when AllowedModules is empty (all allowed) or contains moduleID.
func (p *Profile) IsModuleAllowed(moduleID string) bool {
	if len(p.AllowedModules) == 0 {
		return true
	}
	for _, id := range p.AllowedModules {
		if id == moduleID {
			return true
		}
	}
	return false
}

// IsPortProtected returns true if port/proto matches ProtectedPorts or ProtectedPortRanges.
// Scope-aware: only blocks firewall/network/sysctl modules, not SSH config modules.
func (p *Profile) IsPortProtected(port int, proto string) bool {
	for _, pp := range p.ProtectedPorts {
		if pp == port {
			return true
		}
	}
	for _, r := range p.ProtectedPortRanges {
		if port >= r.Start && port <= r.End {
			if r.Proto == "both" || r.Proto == "" || r.Proto == proto {
				return true
			}
		}
	}
	return false
}

// IsServiceProtected returns true if the service name is in ProtectedServices.
// Scope-aware: only blocks service-disable/restart modules.
func (p *Profile) IsServiceProtected(name string) bool {
	for _, s := range p.ProtectedServices {
		if s == name {
			return true
		}
	}
	return false
}

// IsProcessProtected returns true if the process name is in ProtectedProcesses.
// Scope-aware: only blocks process-kill/restart modules.
func (p *Profile) IsProcessProtected(name string) bool {
	for _, proc := range p.ProtectedProcesses {
		if proc == name {
			return true
		}
	}
	return false
}
