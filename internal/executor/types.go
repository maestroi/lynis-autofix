package executor

// CmdOutput holds the result of running an external command.
type CmdOutput struct {
	Stdout   string
	Stderr   string
	ExitCode int
}

// ServiceStatus describes the current state of a systemd service.
type ServiceStatus struct {
	Name    string
	Active  bool
	Enabled bool
}
