//go:build !windows

package backup

import (
	"os"
	"syscall"

	"github.com/maestroi/hardener/internal/model"
)

func populateOwner(info os.FileInfo, entry *model.RollbackEntry) {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		entry.OrigUID = int(stat.Uid)
		entry.OrigGID = int(stat.Gid)
	}
}
