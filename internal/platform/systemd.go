package platform

// ServiceName returns the system service name for a canonical service identifier.
// On Ubuntu, "ssh" maps to "ssh" (not "sshd" as on RHEL).
func (o OSInfo) ServiceName(canonical string) string {
	switch canonical {
	case "ssh":
		if o.IsUbuntu() {
			return "ssh"
		}
		return "sshd"
	default:
		return canonical
	}
}
