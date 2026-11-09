// Package version holds the version a build was released as.
package version

// Version is set by the release workflow with -ldflags -X: v1.0.0 for a
// release, v1.0.3-dev-<commit12> for a prerelease. Local builds keep "dev".
var Version = "dev"
