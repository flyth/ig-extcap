//go:build !windows

package main

import (
	"io"
	"os"
)

func NewFIFO(path string) (io.WriteCloser, error) {
	return os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
}
