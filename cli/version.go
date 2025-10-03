package cli

import (
	"fmt"
	"os"
	"runtime/debug"
)

// version holds the build version string injected at link-time.
var version = "dev"

// runVersion implements `falcon version` by printing the current build string.
func runVersion(args []string) int {
	if len(args) > 0 {
		fmt.Fprintln(os.Stderr, "falcon version does not accept arguments")
		return 2
	}

	builtVersion := version
	if builtVersion == "" {
		builtVersion = "dev"
	}
	if builtVersion == "dev" {
		if buildInfo, ok := debug.ReadBuildInfo(); ok {
			if v := buildInfo.Main.Version; v != "" && v != "(devel)" {
				builtVersion = v
			}
		}
	}

	fmt.Fprintln(os.Stdout, builtVersion)
	return 0
}

const helpVersion = `# falcon version

Show the CLI build version. Local builds print "dev"; binaries installed via go install or release builds include their tagged version.

Usage:
  falcon version
`
