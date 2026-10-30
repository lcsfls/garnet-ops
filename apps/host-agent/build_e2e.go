//go:build e2e

package main

import "os"

// The end-to-end tests of this repository build the agent with `-tags e2e`: plain HTTP to the local test server, and a fake host
// file system and rpm. Release builds never carry this file.
const allowHTTP = true

func rootDir() string {
	if dir := os.Getenv("GARNETOPS_TEST_ROOT"); dir != "" {
		return dir
	}
	return "/"
}

func rpmBinary() string { return os.Getenv("GARNETOPS_TEST_RPM") }
