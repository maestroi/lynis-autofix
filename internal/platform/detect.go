package platform

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// OSInfo holds detected operating system metadata.
type OSInfo struct {
	Name          string // "ubuntu", "debian", etc.
	Version       string // "22.04"
	KernelVersion string
	Hostname      string
}

// IsUbuntu returns true if the OS is Ubuntu.
func (o OSInfo) IsUbuntu() bool {
	return strings.EqualFold(o.Name, "ubuntu")
}

// Detect reads /etc/os-release and uname to populate OSInfo.
func Detect() (*OSInfo, error) {
	info := &OSInfo{}

	if err := parseOSRelease(info); err != nil {
		// Non-fatal: continue with empty fields on non-Linux systems.
		info.Name = "unknown"
	}

	if hostname, err := os.Hostname(); err == nil {
		info.Hostname = hostname
	}

	return info, nil
}

func parseOSRelease(info *OSInfo) error {
	f, err := os.Open("/etc/os-release")
	if err != nil {
		return fmt.Errorf("opening /etc/os-release: %w", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		v = strings.Trim(v, `"`)
		switch k {
		case "ID":
			info.Name = strings.ToLower(v)
		case "VERSION_ID":
			info.Version = v
		}
	}
	return scanner.Err()
}
