//go:build !linux && !(darwin && cgo)

package ui

func applyPlatformIcon(_ []byte) {}
