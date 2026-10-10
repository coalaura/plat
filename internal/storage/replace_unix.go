//go:build !windows

package storage

import (
	"os"
	"path/filepath"
)

func replaceFile(source, destination string) error {
	directory, err := os.Open(filepath.Dir(destination))
	if err != nil {
		return err
	}

	defer directory.Close()

	err = os.Rename(source, destination)
	if err != nil {
		return err
	}

	return directory.Sync()
}
