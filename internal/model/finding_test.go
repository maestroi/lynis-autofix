package model_test

import (
	"testing"

	"github.com/maestroi/hardener/internal/model"
	"github.com/stretchr/testify/assert"
)

func TestCategoryFromID(t *testing.T) {
	tests := []struct {
		id   string
		want string
	}{
		{"SSH-7408", "SSH"},
		{"KRNL-6000", "KRNL"},
		{"AUTH-9328", "AUTH"},
		{"FIRE-4513", "FIRE"},
		{"NOHYPHEN", "NOHYPHEN"},
		{"", "UNKNOWN"},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			assert.Equal(t, tt.want, model.CategoryFromID(tt.id))
		})
	}
}

func TestSeverity_String(t *testing.T) {
	assert.Equal(t, "info", model.SeverityInfo.String())
	assert.Equal(t, "warning", model.SeverityWarning.String())
	assert.Equal(t, "critical", model.SeverityCritical.String())
}
