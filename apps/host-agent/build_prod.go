//go:build !e2e

package main

// Production builds talk HTTPS only and read the host's own file system.
const allowHTTP = false

func rootDir() string { return "/" }

func rpmBinary() string { return "" }
