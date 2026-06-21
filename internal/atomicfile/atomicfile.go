// Package atomicfile writes a file atomically: data is written to a uniquely
// named temporary file in the destination directory and then renamed into
// place. This means a crash mid-write cannot corrupt the existing file, and
// two writers racing on the same path (e.g. a periodic save loop and a final
// save) cannot clobber a shared temp file — each gets its own temp name and the
// rename is atomic, so the last writer simply wins.
package atomicfile

import (
	"io/fs"
	"os"
	"path/filepath"
)

// Write atomically writes data to path with the given permissions.
func Write(path string, data []byte, perm fs.FileMode) error {
	dir, base := filepath.Split(path)
	if dir == "" {
		dir = "."
	}

	f, err := os.CreateTemp(dir, base+".*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()

	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Chmod(tmp, perm); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}
