package config

// defaults returns the base Config with sensible production defaults.
func defaults() Config {
	return Config{
		Version:  "1",
		Profile:  "server",
		StateDir: "/var/lib/hardener",
		Lynis: LynisConfig{
			Binary:     "/usr/sbin/lynis",
			ReportPath: "/var/log/lynis-report.dat",
			LogPath:    "/var/log/lynis.log",
		},
		Output:           "table",
		ConfirmDangerous: false,
	}
}
