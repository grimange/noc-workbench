package health

import (
	"noc-workbench/internal/collection"
	"strings"
)

// The installed df source reports device identifiers, not filesystem types.
// Only a matching identifier from the same snapshot can establish selection.
// Unknown mount paths remain eligible; pseudo device names and verified runtime
// paths are excluded. All excluded observations remain retained as evidence.
func PersistentFilesystem(e collection.Evidence, all []collection.Evidence) bool {
	for _, i := range all {
		if i.Key != "linux.filesystem.identifier" || i.Resource != e.Resource || i.RunID != e.RunID || i.Quality != "valid" || i.Value.Kind != "text" || !i.ObservedAt.Equal(e.ObservedAt) {
			continue
		}
		device := i.Value.Text
		switch device {
		case "proc", "sysfs", "devtmpfs", "tmpfs", "cgroup", "cgroup2", "udev", "securityfs", "pstore", "debugfs", "tracefs", "fusectl", "mqueue", "hugetlbfs", "configfs", "ramfs", "efivarfs":
			return false
		}
		if strings.HasPrefix(device, "tmpfs[") || strings.HasPrefix(e.Resource, "/run/credentials/") || strings.HasPrefix(e.Resource, "/run/systemd/propagate/") {
			return false
		}
		// Preserve unfamiliar sources and mount paths; df does not prove their type.
		return device != ""
	}
	return false
}
