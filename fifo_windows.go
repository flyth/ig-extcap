package main

import (
	"io"
	"os"
)

func NewFIFO(path string) (io.WriteCloser, error) {
	return os.OpenFile(path, os.O_WRONLY, os.ModeNamedPipe)
}
