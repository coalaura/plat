package storage

import (
	"os"
	"path/filepath"
)

// WriteAtomic never changes the published file until the complete replacement is synced.
func WriteAtomic(path string, data []byte) error {
	return writeFile(path, data, false)
}

// WriteExclusive publishes a complete file without replacing an existing identity.
func WriteExclusive(path string, data []byte) error {
	return writeFile(path, data, true)
}

func writeFile(path string, data []byte, exclusive bool) error {
	directory := filepath.Dir(path)

	err := os.MkdirAll(directory, 0700)
	if err != nil {
		return err
	}

	file, err := os.CreateTemp(directory, ".plat-*")
	if err != nil {
		return err
	}

	defer os.Remove(file.Name())
	defer file.Close()

	err = restrictFile(file)
	if err != nil {
		return err
	}

	_, err = file.Write(data)
	if err != nil {
		return err
	}

	err = file.Sync()
	if err != nil {
		return err
	}

	err = file.Close()
	if err != nil {
		return err
	}

	if exclusive {
		return os.Link(file.Name(), path)
	}

	return replaceFile(file.Name(), path)
}
