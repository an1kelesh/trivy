// Code generated by Wire. DO NOT EDIT.

//go:generate go run github.com/google/wire/cmd/wire
//go:build !wireinject
// +build !wireinject

package server

import (
	"github.com/an1kelesh/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy/pkg/fanal/applier"
	"github.com/aquasecurity/trivy/pkg/fanal/cache"
	"github.com/aquasecurity/trivy/pkg/scanner/langpkg"
	"github.com/aquasecurity/trivy/pkg/scanner/local"
	"github.com/aquasecurity/trivy/pkg/scanner/ospkg"
	"github.com/aquasecurity/trivy/pkg/vulnerability"
)

// Injectors from inject.go:

func initializeScanServer(localArtifactCache cache.LocalArtifactCache) *ScanServer {
	applierApplier := applier.NewApplier(localArtifactCache)
	scanner := ospkg.NewScanner()
	langpkgScanner := langpkg.NewScanner()
	config := db.Config{}
	client := vulnerability.NewClient(config)
	localScanner := local.NewScanner(applierApplier, scanner, langpkgScanner, client)
	scanServer := NewScanServer(localScanner)
	return scanServer
}
