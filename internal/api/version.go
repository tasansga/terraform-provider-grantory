package api

import (
	"fmt"

	"github.com/hashicorp/go-version"
)

// APIVersion must be bumped whenever the HTTP API contracts change.
const APIVersion = "1.1.0"

type FeatureInfo struct {
	Name  string `json:"name"`
	Since string `json:"since"`
}

// Features lists the optional API features and the version they were introduced.
func Features() []FeatureInfo {
	return []FeatureInfo{
		{
			Name:  "requests.list.filter.has_grant",
			Since: "1.0.0",
		},
		{
			Name:  "requests.list.filter.labels",
			Since: "1.0.0",
		},
		{
			Name:  "requests.list.filter.host_labels",
			Since: "1.0.0",
		},
		{
			Name:  "registers.list.filter.labels",
			Since: "1.0.0",
		},
		{
			Name:  "registers.list.filter.host_labels",
			Since: "1.0.0",
		},
		{
			Name:  "requests.embedded_grant",
			Since: "1.0.0",
		},
		{
			Name:  "hosts.labels_patch",
			Since: "1.0.0",
		},
		{
			Name:  "requests.labels_patch",
			Since: "1.0.0",
		},
		{
			Name:  "registers.labels_patch",
			Since: "1.0.0",
		},
		{
			Name:  "requests.unique_key",
			Since: "1.1.0",
		},
	}
}

// Major extracts the major version from a semver-like string.
func Major(versionString string) string {
	parsed, err := version.NewVersion(versionString)
	if err != nil {
		return "unknown"
	}
	segments := parsed.Segments()
	if len(segments) == 0 {
		return "unknown"
	}
	return fmt.Sprintf("%d", segments[0])
}
