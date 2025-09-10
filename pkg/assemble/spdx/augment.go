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

	"github.com/interlynk-io/sbomasm/pkg/assemble/matcher"
	"github.com/interlynk-io/sbomasm/pkg/logger"
	spdx_json "github.com/spdx/tools-golang/json"
	"github.com/spdx/tools-golang/spdx"
	"github.com/spdx/tools-golang/spdx/v2/common"
	spdx_tv "github.com/spdx/tools-golang/tagvalue"
	"sigs.k8s.io/release-utils/version"
)

type augmentMerge struct {
	settings  *MergeSettings
	primary   *spdx.Document
	secondary []*spdx.Document
	matcher   matcher.ComponentMatcher
	index     *matcher.ComponentIndex
}

func newAugmentMerge(ms *MergeSettings) *augmentMerge {
	return &augmentMerge{
		settings:  ms,
		secondary: []*spdx.Document{},
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
		if err := a.processSecondaryBom(sbom); err != nil {
			return fmt.Errorf("failed to process secondary SBOM %d: %w", i+1, err)
		}
	}
	
	// Update creation info
	a.updateCreationInfo()
	
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
			matchedCount++
		} else {
			// Package doesn't exist, add it
			log.Debugf("No match found for package %s, adding as new", pkg.PackageName)
			newPackages = append(newPackages, pkg)
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
	
	// Merge relationships
	a.mergeRelationships(sbom)
	
	// Merge files if present
	a.mergeFiles(sbom)
	
	// Merge other licenses
	a.mergeOtherLicenses(sbom)
	
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

// mergeRelationships merges relationships from secondary SBOM
func (a *augmentMerge) mergeRelationships(sbom *spdx.Document) {
	if len(sbom.Relationships) == 0 {
		return
	}
	
	log := logger.FromContext(*a.settings.Ctx)
	
	// Create relationship map for efficient lookup
	relMap := make(map[string]bool)
	for _, rel := range a.primary.Relationships {
		key := fmt.Sprintf("%s:%s:%s", rel.RefA, rel.Relationship, rel.RefB)
		relMap[key] = true
	}
	
	// Add unique relationships from secondary
	addedCount := 0
	for _, rel := range sbom.Relationships {
		key := fmt.Sprintf("%s:%s:%s", rel.RefA, rel.Relationship, rel.RefB)
		if !relMap[key] {
			a.primary.Relationships = append(a.primary.Relationships, rel)
			relMap[key] = true
			addedCount++
		}
	}
	
	log.Debugf("Merged relationships, added %d new, total: %d", addedCount, len(a.primary.Relationships))
}

// mergeFiles merges files from secondary SBOM
func (a *augmentMerge) mergeFiles(sbom *spdx.Document) {
	if len(sbom.Files) == 0 {
		return
	}
	
	log := logger.FromContext(*a.settings.Ctx)
	
	// Create file map for efficient lookup
	fileMap := make(map[common.ElementID]bool)
	for _, file := range a.primary.Files {
		fileMap[file.FileSPDXIdentifier] = true
	}
	
	// Add unique files from secondary
	addedCount := 0
	for _, file := range sbom.Files {
		if !fileMap[file.FileSPDXIdentifier] {
			a.primary.Files = append(a.primary.Files, file)
			fileMap[file.FileSPDXIdentifier] = true
			addedCount++
		}
	}
	
	log.Debugf("Merged files, added %d new, total: %d", addedCount, len(a.primary.Files))
}

// mergeOtherLicenses merges other licenses from secondary SBOM
func (a *augmentMerge) mergeOtherLicenses(sbom *spdx.Document) {
	if len(sbom.OtherLicenses) == 0 {
		return
	}
	
	// Create license map for efficient lookup
	licenseMap := make(map[string]bool)
	for _, lic := range a.primary.OtherLicenses {
		licenseMap[lic.LicenseIdentifier] = true
	}
	
	// Add unique licenses from secondary
	for _, lic := range sbom.OtherLicenses {
		if !licenseMap[lic.LicenseIdentifier] {
			a.primary.OtherLicenses = append(a.primary.OtherLicenses, lic)
			licenseMap[lic.LicenseIdentifier] = true
		}
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
		// Default to JSON
		return spdx_json.Write(a.primary, writer)
	}
}