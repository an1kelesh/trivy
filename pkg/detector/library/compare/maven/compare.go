package maven

import (
	version "github.com/masahiro331/go-mvn-version"
	"golang.org/x/xerrors"

	dbTypes "github.com/an1kelesh/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/detector/library/compare"
)

// Comparer represents a comparer for maven
type Comparer struct{}

// IsVulnerable checks if the package version is vulnerable to the advisory.
func (n Comparer) IsVulnerable(ver string, advisory dbTypes.Advisory) bool {
	return compare.IsVulnerable(ver, advisory, n.matchVersion)
}

// matchVersion checks if the package version satisfies the given constraint.
func (n Comparer) matchVersion(currentVersion, constraint string) (bool, error) {
	v, err := version.NewVersion(currentVersion)
	if err != nil {
		return false, xerrors.Errorf("maven version error (%s): %s", currentVersion, err)
	}

	c, err := version.NewComparer(constraint)
	if err != nil {
		return false, xerrors.Errorf("maven constraint error (%s): %s", constraint, err)
	}

	return c.Check(v), nil
}
