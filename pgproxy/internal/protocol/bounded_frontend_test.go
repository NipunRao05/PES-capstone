package protocol

import (
	"bytes"
	"encoding/binary"
	"io"
	"strings"
	"testing"
)

func TestFrontendBoundRejectsHeaderBeforeReadingBody(t *testing.T) {
	header := []byte{'Q', 0, 0, 0, 0}
	binary.BigEndian.PutUint32(header[1:], 0x7fffffff)
	_, err := newBoundedFrontendReader(bytes.NewReader(header)).Read(make([]byte, 32))
	if err == nil || !strings.Contains(err.Error(), "bound") {
		t.Fatal("oversized body was not rejected from header")
	}
}
func TestFrontendBoundPreservesMultipleWireMessages(t *testing.T) {
	data := []byte{'Q', 0, 0, 0, 6, '1', 0, 'S', 0, 0, 0, 4}
	got, err := io.ReadAll(newBoundedFrontendReader(bytes.NewReader(data)))
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("wire changed: %v", err)
	}
}
