package api

import (
	"testing"

	"github.com/hashicorp/go-version"
	"github.com/stretchr/testify/assert"
)

func TestFeaturesUniqueAndSemver(t *testing.T) {
	t.Parallel()

	features := Features()
	seen := make(map[string]struct{}, len(features))
	for _, feature := range features {
		assert.NotEmpty(t, feature.Name, "feature name should be set")
		assert.NotEmpty(t, feature.Since, "feature since should be set")
		if _, ok := seen[feature.Name]; ok {
			t.Fatalf("duplicate feature name: %s", feature.Name)
		}
		seen[feature.Name] = struct{}{}
		_, err := version.NewVersion(feature.Since)
		assert.NoError(t, err, "feature since must be valid semver: %s", feature.Since)
	}
}
