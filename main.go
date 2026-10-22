package main

import (
	"fmt"
	"os"
)

const appName = "emudhra-container-scanner"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", appName, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) > 0 {
		return fmt.Errorf("unknown command %q", args[0])
	}
	fmt.Printf("%s\n\nUsage:\n  %s <command>\n\nNo commands are available yet.\n", appName, appName)
	return nil
}
