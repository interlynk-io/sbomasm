// Copyright 2025 Interlynk.io
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package spdx

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/interlynk-io/sbomasm/pkg/assemble/matcher"
	"github.com/interlynk-io/sbomasm/pkg/logger"
	"github.com/interlynk-io/sbomasm/pkg/sbom"
	"github.com/spdx/tools-golang/spdx"
	"github.com/spdx/tools-golang/spdx/v2/common"
	spdx_tv "github.com/spdx/tools-golang/tagvalue"
	"sigs.k8s.io/release-utils/version"
)

type augmentMerge struct {
	settings      *MergeSettings
	primary       *spdx.Document
	secondary     []*spdx.Document
	matcher       matcher.ComponentMatcher
	index         *matcher.ComponentIndex
	processedPkgs map[string]string // Maps secondary pkg IDs to primary pkg IDs (using string representation)
	addedPkgIDs   map[string]bool   // Tracks newly added package IDs (using string representation)
}

func newAugmentMerge(ms *MergeSettings) *augmentMerge {
	return &augmentMerge{
		settings:      ms,
		secondary:     []*spdx.Document{},
		processedPkgs: make(map[string]string),
		addedPkgIDs:   make(map[string]bool),
	}
}

// merge performs the augment merge operation
func (a *augmentMerge) merge() error {
	log := logger.FromContext(*a.settings.Ctx)

	log.Debug("Starting SPDX augment merge")

	// Load primary SBOM
	if err := a.loadPrimaryBom(); err != nil {
		return fmt.Errorf("failed to load primary SBOM: %w", err)
	}

	// Load secondary SBOMs
	if err := a.loadSecondaryBoms(); err != nil {
		return fmt.Errorf("failed to load secondary SBOMs: %w", err)
	}

	// Setup matcher
	if err := a.setupMatcher(); err != nil {
		return fmt.Errorf("failed to setup matcher: %w", err)
	}

	// Build index from primary SBOM packages
	if err := a.buildPrimaryIndex(); err != nil {
		return fmt.Errorf("failed to build package index: %w", err)
	}

	log.Debugf("Processing %d secondary SBOMs", len(a.secondary))

	// Process each secondary SBOM
	for i, sbom := range a.secondary {
		log.Debugf("Processing secondary SBOM %d", i+1)
		// Reset ID tracking for each secondary SBOM
		a.processedPkgs = make(map[string]string)
		a.addedPkgIDs = make(map[string]bool)
		if err := a.processSecondaryBom(sbom); err != nil {
			return fmt.Errorf("failed to process secondary SBOM %d: %w", i+1, err)
		}
	}

	// Update creation info
	a.updateCreationInfo()

	// Ensure proper DESCRIBES relationships according to SPDX spec
	a.ensurePrimaryDescribes()

	// Write the merged SBOM
	return a.writeSBOM()
}

// loadPrimaryBom loads the primary SBOM from file
func (a *augmentMerge) loadPrimaryBom() error {
	log := logger.FromContext(*a.settings.Ctx)

	primaryPath := a.settings.Assemble.PrimaryFile
	log.Debugf("Loading primary SBOM from %s", primaryPath)

	doc, err := loadBom(*a.settings.Ctx, primaryPath)
	if err != nil {
		return err
	}

	a.primary = doc
	return nil
}

// loadSecondaryBoms loads all secondary SBOMs
func (a *augmentMerge) loadSecondaryBoms() error {
	log := logger.FromContext(*a.settings.Ctx)

	for _, path := range a.settings.Input.Files {
		log.Debugf("Loading secondary SBOM from %s", path)
		doc, err := loadBom(*a.settings.Ctx, path)
		if err != nil {
			return err
		}
		a.secondary = append(a.secondary, doc)
	}

	return nil
}

// setupMatcher creates the composite component matcher
func (a *augmentMerge) setupMatcher() error {
	factory := matcher.NewDefaultMatcherFactory(&matcher.MatcherConfig{
		Strategy:      "composite",
		StrictVersion: false, // For augment, we typically want to match regardless of version
		FuzzyMatch:    false,
		TypeMatch:     true,
		MinConfidence: 50,
	})

	m, err := factory.GetMatcher("composite")
	if err != nil {
		return err
	}

	a.matcher = m
	return nil
}

// buildPrimaryIndex builds an index of primary SBOM packages
func (a *augmentMerge) buildPrimaryIndex() error {
	log := logger.FromContext(*a.settings.Ctx)

	components := []matcher.Component{}

	// Add all packages
	for i := range a.primary.Packages {
		pkg := a.primary.Packages[i]
		components = append(components, matcher.NewSPDXComponent(pkg))
	}

	log.Debugf("Building index with %d packages from primary SBOM", len(components))
	a.index = matcher.BuildIndex(components)

	return nil
}

// processSecondaryBom processes a single secondary SBOM
func (a *augmentMerge) processSecondaryBom(sbom *spdx.Document) error {
	log := logger.FromContext(*a.settings.Ctx)

	if len(sbom.Packages) == 0 {
		return nil
	}

	newPackages := []*spdx.Package{}
	matchedCount := 0
	addedCount := 0

	for _, pkg := range sbom.Packages {
		unifiedPkg := matcher.NewSPDXComponent(pkg)

		// Find matching package in primary
		matchResult := a.index.FindBestMatch(unifiedPkg, a.matcher)

		if matchResult != nil {
			// Package exists in primary, merge it
			log.Debugf("Found match for package %s with confidence %d", pkg.PackageName, matchResult.Confidence)
			primaryPkg := matchResult.Primary.GetOriginal().(*spdx.Package)
			a.mergePackage(primaryPkg, pkg)
			// Track the mapping from secondary to primary package ID
			a.processedPkgs[string(pkg.PackageSPDXIdentifier)] = string(primaryPkg.PackageSPDXIdentifier)
			matchedCount++
		} else {
			// Package doesn't exist, add it
			log.Debugf("No match found for package %s, adding as new", pkg.PackageName)
			newPackages = append(newPackages, pkg)
			// Track as newly added package
			a.addedPkgIDs[string(pkg.PackageSPDXIdentifier)] = true
			a.processedPkgs[string(pkg.PackageSPDXIdentifier)] = string(pkg.PackageSPDXIdentifier)
			addedCount++
		}
	}

	// Add new packages to primary SBOM
	if len(newPackages) > 0 {
		a.primary.Packages = append(a.primary.Packages, newPackages...)

		// Update index with new packages
		for _, pkg := range newPackages {
			a.index.AddComponent(matcher.NewSPDXComponent(pkg))
		}
	}

	// Merge relationships for processed packages only
	a.mergeSelectiveRelationships(sbom)

	// Merge other licenses for processed packages only
	a.mergeSelectiveOtherLicenses(sbom)

	log.Debugf("Processed secondary SBOM: %d matched, %d added", matchedCount, addedCount)

	return nil
}

// mergePackage merges fields from secondary package into primary
func (a *augmentMerge) mergePackage(primary, secondary *spdx.Package) {
	mergeMode := a.settings.Assemble.MergeMode

	if mergeMode == "overwrite" {
		a.overwritePackageFields(primary, secondary)
	} else {
		// Default: if-missing-or-empty
		a.fillMissingPackageFields(primary, secondary)
	}
}

// fillMissingPackageFields fills only missing/empty fields in primary
func (a *augmentMerge) fillMissingPackageFields(primary, secondary *spdx.Package) {
	// Basic fields
	if primary.PackageDescription == "" && secondary.PackageDescription != "" {
		primary.PackageDescription = secondary.PackageDescription
	}

	if primary.PackageDownloadLocation == "" && secondary.PackageDownloadLocation != "" {
		primary.PackageDownloadLocation = secondary.PackageDownloadLocation
	}

	if primary.PackageHomePage == "" && secondary.PackageHomePage != "" {
		primary.PackageHomePage = secondary.PackageHomePage
	}

	if primary.PackageSourceInfo == "" && secondary.PackageSourceInfo != "" {
		primary.PackageSourceInfo = secondary.PackageSourceInfo
	}

	if primary.PackageCopyrightText == "" && secondary.PackageCopyrightText != "" {
		primary.PackageCopyrightText = secondary.PackageCopyrightText
	}

	if primary.PackageLicenseConcluded == "" && secondary.PackageLicenseConcluded != "" {
		primary.PackageLicenseConcluded = secondary.PackageLicenseConcluded
	}

	if primary.PackageLicenseDeclared == "" && secondary.PackageLicenseDeclared != "" {
		primary.PackageLicenseDeclared = secondary.PackageLicenseDeclared
	}

	if primary.PackageLicenseComments == "" && secondary.PackageLicenseComments != "" {
		primary.PackageLicenseComments = secondary.PackageLicenseComments
	}

	// Supplier/Originator
	if primary.PackageSupplier == nil && secondary.PackageSupplier != nil {
		primary.PackageSupplier = secondary.PackageSupplier
	}

	if primary.PackageOriginator == nil && secondary.PackageOriginator != nil {
		primary.PackageOriginator = secondary.PackageOriginator
	}

	// Checksums
	if len(primary.PackageChecksums) == 0 && len(secondary.PackageChecksums) > 0 {
		primary.PackageChecksums = secondary.PackageChecksums
	}

	// External references (including purl and CPE)
	if len(primary.PackageExternalReferences) == 0 && len(secondary.PackageExternalReferences) > 0 {
		primary.PackageExternalReferences = secondary.PackageExternalReferences
	} else if len(secondary.PackageExternalReferences) > 0 {
		// Merge external references, avoiding duplicates
		existingRefs := make(map[string]bool)
		for _, ref := range primary.PackageExternalReferences {
			key := fmt.Sprintf("%s:%s:%s", ref.Category, ref.RefType, ref.Locator)
			existingRefs[key] = true
		}

		for _, ref := range secondary.PackageExternalReferences {
			key := fmt.Sprintf("%s:%s:%s", ref.Category, ref.RefType, ref.Locator)
			if !existingRefs[key] {
				primary.PackageExternalReferences = append(primary.PackageExternalReferences, ref)
			}
		}
	}

	// Primary package purpose
	if primary.PrimaryPackagePurpose == "" && secondary.PrimaryPackagePurpose != "" {
		primary.PrimaryPackagePurpose = secondary.PrimaryPackagePurpose
	}
}

// overwritePackageFields overwrites primary fields with secondary values
func (a *augmentMerge) overwritePackageFields(primary, secondary *spdx.Package) {
	// Basic fields
	if secondary.PackageDescription != "" {
		primary.PackageDescription = secondary.PackageDescription
	}

	if secondary.PackageDownloadLocation != "" {
		primary.PackageDownloadLocation = secondary.PackageDownloadLocation
	}

	if secondary.PackageHomePage != "" {
		primary.PackageHomePage = secondary.PackageHomePage
	}

	if secondary.PackageSourceInfo != "" {
		primary.PackageSourceInfo = secondary.PackageSourceInfo
	}

	if secondary.PackageCopyrightText != "" {
		primary.PackageCopyrightText = secondary.PackageCopyrightText
	}

	if secondary.PackageLicenseConcluded != "" {
		primary.PackageLicenseConcluded = secondary.PackageLicenseConcluded
	}

	if secondary.PackageLicenseDeclared != "" {
		primary.PackageLicenseDeclared = secondary.PackageLicenseDeclared
	}

	if secondary.PackageLicenseComments != "" {
		primary.PackageLicenseComments = secondary.PackageLicenseComments
	}

	// Supplier/Originator
	if secondary.PackageSupplier != nil {
		primary.PackageSupplier = secondary.PackageSupplier
	}

	if secondary.PackageOriginator != nil {
		primary.PackageOriginator = secondary.PackageOriginator
	}

	// Checksums
	if len(secondary.PackageChecksums) > 0 {
		primary.PackageChecksums = secondary.PackageChecksums
	}

	// External references
	if len(secondary.PackageExternalReferences) > 0 {
		primary.PackageExternalReferences = secondary.PackageExternalReferences
	}

	// Primary package purpose
	if secondary.PrimaryPackagePurpose != "" {
		primary.PrimaryPackagePurpose = secondary.PrimaryPackagePurpose
	}
}

// mergeSelectiveRelationships merges only relationships involving processed packages
func (a *augmentMerge) mergeSelectiveRelationships(sbom *spdx.Document) {
	if len(sbom.Relationships) == 0 {
		return
	}

	log := logger.FromContext(*a.settings.Ctx)

	// Build set of all valid IDs in primary SBOM
	validIDs := a.buildValidIDSet()

	// Create relationship map for efficient lookup
	relMap := make(map[string]bool)
	for _, rel := range a.primary.Relationships {
		key := fmt.Sprintf("%s:%s:%s", rel.RefA, rel.Relationship, rel.RefB)
		relMap[key] = true
	}

	// Process relationships from secondary SBOM
	addedCount := 0
	skippedCount := 0
	for _, rel := range sbom.Relationships {
		// Skip DESCRIBES relationships from secondary SBOMs
		// These should not be copied as per SPDX specification
		if rel.Relationship == common.TypeRelationshipDescribe {
			skippedCount++
			continue
		}

		// Check if relationship involves a processed package
		if !a.isRelationshipRelevant(rel) {
			skippedCount++
			continue
		}

		// Resolve IDs to their primary SBOM equivalents
		resolvedRefA := a.resolveDocElementID(rel.RefA)
		resolvedRefB := a.resolveDocElementID(rel.RefB)

		// Convert to strings for validation
		resolvedRefAStr := a.docElementIDToString(resolvedRefA)
		resolvedRefBStr := a.docElementIDToString(resolvedRefB)

		// Validate both IDs exist in primary SBOM
		if !validIDs[resolvedRefAStr] || !validIDs[resolvedRefBStr] {
			log.Debugf("Skipping relationship %s->%s: one or both IDs not valid in primary SBOM",
				resolvedRefAStr, resolvedRefBStr)
			skippedCount++
			continue
		}

		// Create new relationship with resolved IDs
		newRel := &spdx.Relationship{
			RefA:                resolvedRefA,
			RefB:                resolvedRefB,
			Relationship:        rel.Relationship,
			RelationshipComment: rel.RelationshipComment,
		}

		// Check for duplicates
		key := fmt.Sprintf("%s:%s:%s", newRel.RefA, newRel.Relationship, newRel.RefB)
		if !relMap[key] {
			a.primary.Relationships = append(a.primary.Relationships, newRel)
			relMap[key] = true
			addedCount++
		}
	}

	log.Debugf("Merged relationships: added %d, skipped %d, total: %d",
		addedCount, skippedCount, len(a.primary.Relationships))
}

// mergeSelectiveOtherLicenses merges only licenses referenced by processed packages
func (a *augmentMerge) mergeSelectiveOtherLicenses(sbom *spdx.Document) {
	if len(sbom.OtherLicenses) == 0 {
		return
	}

	log := logger.FromContext(*a.settings.Ctx)

	// Collect license IDs referenced by processed packages
	referencedLicenses := a.collectReferencedLicenses(sbom)

	// Create license map for efficient lookup
	licenseMap := make(map[string]bool)
	for _, lic := range a.primary.OtherLicenses {
		licenseMap[lic.LicenseIdentifier] = true
	}

	// Add only referenced licenses from secondary
	addedCount := 0
	for _, lic := range sbom.OtherLicenses {
		if referencedLicenses[lic.LicenseIdentifier] && !licenseMap[lic.LicenseIdentifier] {
			a.primary.OtherLicenses = append(a.primary.OtherLicenses, lic)
			licenseMap[lic.LicenseIdentifier] = true
			addedCount++
		}
	}

	log.Debugf("Merged other licenses: added %d, total: %d", addedCount, len(a.primary.OtherLicenses))
}

// buildValidIDSet builds a set of all valid SPDX IDs in the primary SBOM
func (a *augmentMerge) buildValidIDSet() map[string]bool {
	validIDs := make(map[string]bool)

	// Add document ID
	validIDs[string(a.primary.SPDXIdentifier)] = true

	// Add all package IDs
	for _, pkg := range a.primary.Packages {
		validIDs[string(pkg.PackageSPDXIdentifier)] = true
	}

	// Add all file IDs
	for _, file := range a.primary.Files {
		validIDs[string(file.FileSPDXIdentifier)] = true
	}

	// Add all snippet IDs if present
	for _, snippet := range a.primary.Snippets {
		validIDs[string(snippet.SnippetSPDXIdentifier)] = true
	}

	return validIDs
}

// isRelationshipRelevant checks if a relationship involves a processed package
func (a *augmentMerge) isRelationshipRelevant(rel *spdx.Relationship) bool {
	// Convert DocElementID to string for lookup
	refAStr := a.docElementIDToString(rel.RefA)
	refBStr := a.docElementIDToString(rel.RefB)

	// Check if either end of the relationship is a processed package
	_, refAProcessed := a.processedPkgs[refAStr]
	_, refBProcessed := a.processedPkgs[refBStr]

	return refAProcessed || refBProcessed
}

// resolveDocElementID resolves a secondary SBOM DocElementID to its primary SBOM equivalent
func (a *augmentMerge) resolveDocElementID(id common.DocElementID) common.DocElementID {
	// Convert to string for lookup
	idStr := a.docElementIDToString(id)

	// If this ID was mapped during package processing, use the mapped ID
	if mappedIDStr, exists := a.processedPkgs[idStr]; exists {
		// Convert back to DocElementID
		return a.stringToDocElementID(mappedIDStr)
	}
	// Otherwise, return the ID as-is (for document IDs, etc.)
	return id
}

// docElementIDToString converts a DocElementID to a string representation
func (a *augmentMerge) docElementIDToString(id common.DocElementID) string {
	if id.SpecialID != "" {
		return id.SpecialID
	}
	if id.DocumentRefID != "" {
		return fmt.Sprintf("%s:%s", id.DocumentRefID, id.ElementRefID)
	}
	return string(id.ElementRefID)
}

// stringToDocElementID converts a string back to DocElementID
func (a *augmentMerge) stringToDocElementID(s string) common.DocElementID {
	// Check for special IDs
	if s == "NONE" || s == "NOASSERTION" {
		return common.DocElementID{SpecialID: s}
	}

	// Check for document reference
	if idx := strings.Index(s, ":"); idx > 0 {
		return common.DocElementID{
			DocumentRefID: s[:idx],
			ElementRefID:  common.ElementID(s[idx+1:]),
		}
	}

	// Simple element ID
	return common.DocElementID{ElementRefID: common.ElementID(s)}
}

// collectReferencedLicenses collects license IDs referenced by processed packages
func (a *augmentMerge) collectReferencedLicenses(sbom *spdx.Document) map[string]bool {
	licenses := make(map[string]bool)

	for _, pkg := range sbom.Packages {
		// Only process packages that were added or merged
		if _, processed := a.processedPkgs[string(pkg.PackageSPDXIdentifier)]; !processed {
			continue
		}

		// Extract license identifiers from concluded and declared licenses
		a.extractLicenseIDs(pkg.PackageLicenseConcluded, licenses)
		a.extractLicenseIDs(pkg.PackageLicenseDeclared, licenses)
	}

	return licenses
}

// extractLicenseIDs extracts license identifiers from a license expression
func (a *augmentMerge) extractLicenseIDs(licenseExpr string, licenses map[string]bool) {
	if licenseExpr == "" || licenseExpr == "NOASSERTION" || licenseExpr == "NONE" {
		return
	}

	// Simple extraction - this could be enhanced to properly parse SPDX license expressions
	// For now, we'll look for LicenseRef- prefixed identifiers
	if len(licenseExpr) > 11 && licenseExpr[:11] == "LicenseRef-" {
		licenses[licenseExpr] = true
	}
}

// updateCreationInfo updates the primary SBOM creation info
func (a *augmentMerge) updateCreationInfo() {
	log := logger.FromContext(*a.settings.Ctx)

	// Update creation timestamp
	a.primary.CreationInfo.Created = utcNowTime()

	// Add sbomasm as a creator tool
	sbomasmCreator := common.Creator{
		CreatorType: "Tool",
		Creator:     fmt.Sprintf("sbomasm-%s", version.GetVersionInfo().GitVersion),
	}

	// Check if sbomasm is already in creators
	found := false
	for _, creator := range a.primary.CreationInfo.Creators {
		if creator.CreatorType == sbomasmCreator.CreatorType && creator.Creator == sbomasmCreator.Creator {
			found = true
			break
		}
	}

	if !found {
		a.primary.CreationInfo.Creators = append(a.primary.CreationInfo.Creators, sbomasmCreator)
	}

	log.Debug("Updated creation info with timestamp and tool information")
}

// findPrimaryPackage finds the primary package in the primary SBOM
// It looks for a package that has a DESCRIBES relationship from the document
// If no DESCRIBES exists and there's only one package, that's considered the primary
func (a *augmentMerge) findPrimaryPackage() *spdx.Package {
	// Look for existing DESCRIBES relationship
	for _, rel := range a.primary.Relationships {
		if rel.Relationship == common.TypeRelationshipDescribe {
			refAStr := a.docElementIDToString(rel.RefA)
			refBStr := a.docElementIDToString(rel.RefB)

			// Check if it's a document -> package DESCRIBES relationship
			if refAStr == string(a.primary.SPDXIdentifier) || refAStr == "DOCUMENT" {
				// Find the package being described
				for _, pkg := range a.primary.Packages {
					if string(pkg.PackageSPDXIdentifier) == refBStr {
						return pkg
					}
				}
			}
		}
	}

	// If no DESCRIBES found and there's only one package in original primary SBOM
	// (before augmentation), that's the primary package
	if len(a.primary.Packages) == 1 {
		return a.primary.Packages[0]
	}

	// If we have multiple packages but no DESCRIBES, use the first package
	// This is a fallback - ideally the primary SBOM should have proper DESCRIBES
	// if len(a.primary.Packages) > 0 {
	// 	return a.primary.Packages[0]
	// }


	return nil
}

// ensurePrimaryDescribes ensures there's a DESCRIBES relationship from document to primary package
// This is required by SPDX spec when there are multiple packages
func (a *augmentMerge) ensurePrimaryDescribes() {
	log := logger.FromContext(*a.settings.Ctx)

	// Find the primary package
	primaryPkg := a.findPrimaryPackage()
	if primaryPkg == nil {
		log.Warn("No primary package found in augmented SBOM")
		return
	}

	// Check if we already have a DESCRIBES to the primary package
	hasDescribes := false
	for _, rel := range a.primary.Relationships {
		if rel.Relationship == common.TypeRelationshipDescribe {
			refAStr := a.docElementIDToString(rel.RefA)
			refBStr := a.docElementIDToString(rel.RefB)

			if (refAStr == string(a.primary.SPDXIdentifier) || refAStr == "DOCUMENT") &&
				refBStr == string(primaryPkg.PackageSPDXIdentifier) {
				hasDescribes = true
				break
			}
		}
	}

	// If we have multiple packages but no DESCRIBES to primary, add it
	if !hasDescribes && len(a.primary.Packages) > 1 {
		describedRel := &spdx.Relationship{
			RefA:                common.MakeDocElementID("", string(a.primary.SPDXIdentifier)),
			RefB:                common.MakeDocElementID("", string(primaryPkg.PackageSPDXIdentifier)),
			Relationship:        common.TypeRelationshipDescribe,
			RelationshipComment: "Primary package DESCRIBES relationship added by sbomasm augment merge",
		}
		a.primary.Relationships = append(a.primary.Relationships, describedRel)
		log.Debugf("Added DESCRIBES relationship from document to primary package %s", primaryPkg.PackageName)
	}

	// Remove any DESCRIBES relationships to non-primary packages
	// This ensures compliance with SPDX spec
	filteredRels := []*spdx.Relationship{}
	removedCount := 0
	for _, rel := range a.primary.Relationships {
		if rel.Relationship == common.TypeRelationshipDescribe {
			refAStr := a.docElementIDToString(rel.RefA)
			refBStr := a.docElementIDToString(rel.RefB)

			// Keep only DESCRIBES from document to primary package
			if (refAStr == string(a.primary.SPDXIdentifier) || refAStr == "DOCUMENT") &&
				refBStr != string(primaryPkg.PackageSPDXIdentifier) {
				// This is a DESCRIBES to a non-primary package, skip it
				removedCount++
				continue
			}
		}
		filteredRels = append(filteredRels, rel)
	}

	if removedCount > 0 {
		a.primary.Relationships = filteredRels
		log.Debugf("Removed %d DESCRIBES relationships to non-primary packages", removedCount)
	}
}

// writeSBOM writes the augmented SBOM to output
func (a *augmentMerge) writeSBOM() error {
	log := logger.FromContext(*a.settings.Ctx)

	outputPath := a.settings.Output.File
	format := a.settings.Output.FileFormat

	log.Debugf("Writing augmented SBOM to %s in %s format", outputPath, format)

	// Determine output writer
	var writer io.Writer
	if outputPath == "" {
		writer = os.Stdout
	} else {
		file, err := os.Create(outputPath)
		if err != nil {
			return fmt.Errorf("failed to create output file: %w", err)
		}
		defer file.Close()
		writer = file
	}

	// Write based on format
	if format == "tag-value" || format == "tv" {
		return spdx_tv.Write(a.primary, writer)
	} else {
		return sbom.WriteSBOM(writer, &sbom.SPDXDocument{Doc: a.primary})
	}
}
