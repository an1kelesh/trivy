package redos

import (
	"time"

	version "github.com/knqyf263/go-rpm-version"
	"golang.org/x/xerrors"
	"k8s.io/utils/clock"

	redosoval "github.com/an1kelesh/trivy-db/pkg/vulnsrc/redos"
	osver "github.com/aquasecurity/trivy/pkg/detector/ospkg/version"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/scanner/utils"
	"github.com/aquasecurity/trivy/pkg/types"
)

var (
	eolDates = map[string]time.Time{
		"7": time.Date(2024, 7, 23, 23, 59, 59, 0, time.UTC),
		"8": time.Date(2029, 7, 18, 23, 59, 59, 0, time.UTC),
	}
)

// Scanner implements redos vulnerability scanner
type Scanner struct {
	vs    *redosoval.VulnSrc
	clock clock.Clock
}

// NewScanner is the factory method to return redos vulnerabilities
func NewScanner() *Scanner {
	return &Scanner{
		vs:    redosoval.NewVulnSrc(),
		clock: clock.RealClock{},
	}
}

// Detect scans and return vulnerability in RedOS scanner
func (s *Scanner) Detect(osVer string, _ *ftypes.Repository, pkgs []ftypes.Package) ([]types.DetectedVulnerability, error) {
	log.Logger.Info("Detecting RedOS Linux vulnerabilities...")

	osVer = osver.Major(osVer)
	log.Logger.Debugf("RedOS Linux: os version: %s", osVer)
	log.Logger.Debugf("RedOS Linux: the number of packages: %d", len(pkgs))

	var vulns []types.DetectedVulnerability
	for _, pkg := range pkgs {
		advisories, err := s.vs.Get(osVer, pkg.Name)
		if err != nil {
			return nil, xerrors.Errorf("failed to get RedOS Linux advisory: %w", err)
		}

		installed := utils.FormatVersion(pkg)
		installedVersion := version.NewVersion(installed)
		for _, adv := range advisories {

			fixedVersion := version.NewVersion(adv.FixedVersion)
			vuln := types.DetectedVulnerability{
				VulnerabilityID:  adv.VulnerabilityID,
				PkgID:            pkg.ID,
				PkgName:          pkg.Name,
				InstalledVersion: installed,
				PkgRef:           pkg.Ref,
				Layer:            pkg.Layer,
				Custom:           adv.Custom,
				DataSource:       adv.DataSource,
			}
			if installedVersion.LessThan(fixedVersion) {
				vuln.FixedVersion = adv.FixedVersion
				vulns = append(vulns, vuln)
			}
		}
	}
	return vulns, nil
}

// IsSupportedVersion checks if the version is supported.
func (s *Scanner) IsSupportedVersion(osFamily ftypes.OSType, osVer string) bool {
	return osver.Supported(s.clock, eolDates, osFamily, osver.Major(osVer))
}
