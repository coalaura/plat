//go:build !windows

package storage

import "os"

func restrictFile(file *os.File) error {
	return file.Chmod(0600)
}
