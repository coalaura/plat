package main

import (
	"os"
	"strings"
)

func OpenFileForReading(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY, 0)
}

func OpenFileForWriting(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
}

func EscapeYamlPath(key string) string {
	return strings.ReplaceAll(key, "'", `\'`)
}
