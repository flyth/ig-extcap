package main

import (
	"io"

	"github.com/flyth/npipe"
)

func NewFIFO(path string) (io.WriteCloser, error) {
	return npipe.Dial(path)
}
