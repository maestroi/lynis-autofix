//go:build windows

package backup

import (
	"os"

	"github.com/maestroi/hardener/internal/model"
)

func populateOwner(_ os.FileInfo, _ *model.RollbackEntry) {
	// Windows does not expose UID/GID via syscall.Stat_t.
}
