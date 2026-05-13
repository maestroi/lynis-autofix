package lynis

import (
	"bufio"
	"bytes"
	"fmt"
	"strconv"
	"strings"

	"github.com/maestroi/hardener/internal/model"
)

// ParseReportBytes parses a Lynis report (lynis-report.dat) from raw bytes.
func ParseReportBytes(data []byte) ([]*model.Finding, error) {
	var findings []*model.Finding
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if f := parseWarningLine(line); f != nil {
			findings = append(findings, f)
			continue
		}
		if f := parseSuggestionLine(line); f != nil {
			findings = append(findings, f)
		}
	}
	return findings, scanner.Err()
}

// ScoreFromBytes extracts the hardening_index value from a Lynis report.
// Returns 0 if no score line is found.
func ScoreFromBytes(data []byte) (int, error) {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "hardening_index=") {
			continue
		}
		val := strings.TrimPrefix(line, "hardening_index=")
		n, err := strconv.Atoi(strings.TrimSpace(val))
		if err != nil {
			return 0, fmt.Errorf("invalid hardening_index value %q: %w", val, err)
		}
		return n, nil
	}
	return 0, scanner.Err()
}

// parseWarningLine parses a line like: warning[]=SSH-7408|description|details
func parseWarningLine(line string) *model.Finding {
	const prefix = "warning[]="
	if !strings.HasPrefix(line, prefix) {
		return nil
	}
	return parseFindingLine(strings.TrimPrefix(line, prefix), model.SeverityWarning, line)
}

// parseSuggestionLine parses a line like: suggestion[]=KRNL-6000|description|details
func parseSuggestionLine(line string) *model.Finding {
	const prefix = "suggestion[]="
	if !strings.HasPrefix(line, prefix) {
		return nil
	}
	return parseFindingLine(strings.TrimPrefix(line, prefix), model.SeverityInfo, line)
}

func parseFindingLine(value string, severity model.Severity, raw string) *model.Finding {
	parts := strings.SplitN(value, "|", 3)
	if len(parts) < 2 {
		return nil
	}
	id := strings.TrimSpace(parts[0])
	if id == "" {
		return nil
	}
	desc := strings.TrimSpace(parts[1])
	var details []string
	if len(parts) == 3 && strings.TrimSpace(parts[2]) != "" {
		details = []string{strings.TrimSpace(parts[2])}
	}
	return &model.Finding{
		ID:          id,
		Category:    model.CategoryFromID(id),
		Description: desc,
		Severity:    severity,
		Details:     details,
		Source:      "lynis",
		Raw:         raw,
	}
}
