// Copyright 2026 Interlynk.io
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package gsbom

import (
	"context"
	"fmt"
	"strings"

	"github.com/interlynk-io/sbomasm/v2/pkg/logger"
	"go.uber.org/zap"
)

// StrictChecker performs strict mode validation checks.
// These checks generate warnings in default mode, but become hard errors
// when --strict is enabled.
type StrictChecker struct {
	Warnings []error
	log      *zap.SugaredLogger
}

// NewStrictChecker creates a new strict mode checker.
func NewStrictChecker(log *zap.SugaredLogger) *StrictChecker {
	return &StrictChecker{
		Warnings: []error{},
		log:      log,
	}
}

// Check runs all strict mode validations and returns warnings.
// When strict mode is enabled, these warnings become errors.
func (s *StrictChecker) Check(component Component, sourcePath string) {
	s.checkMissingLicense(component)
	s.checkVendoredWithoutPedigree(component, sourcePath)
	s.checkMissingHashes(component)
	s.checkMissingDistributionRef(component)
	s.checkLibraryWithoutSupplier(component)
}

// checkMissingLicense validates component has a license field.
// NTIA minimum requirement.
func (s *StrictChecker) checkMissingLicense(c Component) {
	licenseStr := c.License.String()
	if strings.TrimSpace(licenseStr) == "" || strings.TrimSpace(licenseStr) == "NOASSERTION" || strings.TrimSpace(licenseStr) == "NONE" {
		s.log.Debugf("component %s@%s has no license field", c.Name, c.Version)
		s.Warnings = append(s.Warnings,
			fmt.Errorf("component %s@%s has no license field", c.Name, c.Version))
	}
}

// checkVendoredWithoutPedigree detects vendored code without pedigree.
// Vendored code (under vendor/, thirdparty/, src/*/) must declare origin via pedigree.
func (s *StrictChecker) checkVendoredWithoutPedigree(c Component, sourcePath string) {
	// Skip if pedigree is already present
	if c.Pedigree != nil && (len(c.Pedigree.Ancestors) > 0 || len(c.Pedigree.Patches) > 0) {
		return
	}

	// Check if path looks vendored
	if isVendoredPath(sourcePath) {
		s.log.Debugf("component %s@%s looks vendored but has no pedigree (path: %s)", c.Name, c.Version, sourcePath)
		s.Warnings = append(s.Warnings,
			fmt.Errorf("component %s@%s looks vendored but has no pedigree", c.Name, c.Version))
	}
}

// isVendoredPath checks if the source path indicates vendored code.
func isVendoredPath(path string) bool {
	pathLower := strings.ToLower(path)
	// Check for common vendored code paths
	return strings.Contains(pathLower, "vendor/") ||
		strings.Contains(pathLower, "thirdparty/") ||
		strings.Contains(pathLower, "third_party/")
}

// checkMissingHashes validates component has at least one hash.
// NTIA minimum requirement; needed for supply-chain attestation.
func (s *StrictChecker) checkMissingHashes(c Component) {
	if len(c.Hashes) == 0 {
		s.log.Debugf("component %s@%s has no hash", c.Name, c.Version)
		s.Warnings = append(s.Warnings,
			fmt.Errorf("component %s@%s has no hash", c.Name, c.Version))
	}
}

// checkMissingDistributionRef validates component has a distribution URL.
// Auditors need "where did you fetch this from".
func (s *StrictChecker) checkMissingDistributionRef(c Component) {
	hasDistribution := false
	for _, ref := range c.ExternalRefs {
		if ref.Type == "distribution" && strings.TrimSpace(ref.URL) != "" {
			hasDistribution = true
			break
		}
	}

	if !hasDistribution {
		s.log.Debugf("component %s@%s has no distribution URL", c.Name, c.Version)
		s.Warnings = append(s.Warnings,
			fmt.Errorf("component %s@%s has no distribution URL", c.Name, c.Version))
	}
}

// checkLibraryWithoutSupplier validates library components have a supplier.
// NTIA minimum element.
func (s *StrictChecker) checkLibraryWithoutSupplier(c Component) {
	if c.Type == "library" && strings.TrimSpace(c.Supplier.Name) == "" && strings.TrimSpace(c.Supplier.Email) == "" {
		s.log.Debugf("component %s@%s has no supplier", c.Name, c.Version)
		s.Warnings = append(s.Warnings,
			fmt.Errorf("component %s@%s has no supplier", c.Name, c.Version))
	}
}

// CheckPurlCollision validates that a component's purl differs from its ancestor purls.
// This is ALWAYS a hard error, even without --strict.
func CheckPurlCollision(component Component) error {
	if component.Pedigree == nil || len(component.Pedigree.Ancestors) == 0 {
		return nil
	}

	for _, ancestor := range component.Pedigree.Ancestors {
		if ancestor.PURL == component.PURL && component.PURL != "" {
			return fmt.Errorf("component %s@%s purl collides with pedigree.ancestors[]: %s",
				component.Name, component.Version, component.PURL)
		}
	}

	return nil
}

// ValidateStrictChecks runs strict checks on all components.
// Returns warnings (default mode) or error (strict mode).
func ValidateStrictChecks(ctx *context.Context, components []Component, strict bool) ([]error, error) {
	var log *zap.SugaredLogger
	if ctx != nil {
		log = logger.FromContext(*ctx)
	} else {
		log = zap.NewNop().Sugar()
	}
	checker := NewStrictChecker(log)

	log.Debugf("validating %d components (strict=%v)", len(components), strict)

	for _, c := range components {
		checker.Check(c, c.SourcePath)
	}

	log.Debugf("strict validation complete: %d warnings", len(checker.Warnings))

	if strict && len(checker.Warnings) > 0 {
		return checker.Warnings, fmt.Errorf("strict mode validation failed")
	}

	return checker.Warnings, nil
}
