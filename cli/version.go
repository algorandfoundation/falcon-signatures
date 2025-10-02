package cli

import (
	"fmt"
	"os"
)

// version holds the build version string injected at link-time.
var version = "dev"

// runVersion implements `falcon version` by printing the current build string.
func runVersion(args []string) int {
	if len(args) > 0 {
		fmt.Fprintln(os.Stderr, "falcon version does not accept arguments")
		return 2
	}

	fmt.Fprintln(os.Stdout, version)
	return 0
}

const helpVersion = `# falcon version

Show the CLI build version. Local builds print "dev"; released binaries include their release version.

Usage:
  falcon version
`
