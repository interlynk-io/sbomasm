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

package cdx

import (
	"fmt"
	"io"
	"os"

	cydx "github.com/CycloneDX/cyclonedx-go"
	"github.com/interlynk-io/sbomasm/pkg/assemble/matcher"
	"github.com/interlynk-io/sbomasm/pkg/logger"
	"github.com/samber/lo"
	"sigs.k8s.io/release-utils/version"
)

type augmentMerge struct {
	settings  *MergeSettings
	primary   *cydx.BOM
	secondary []*cydx.BOM
	matcher   matcher.ComponentMatcher
	index     *matcher.ComponentIndex
}

func newAugmentMerge(ms *MergeSettings) *augmentMerge {
	return &augmentMerge{
		settings:  ms,
		secondary: []*cydx.BOM{},
	}
}

// merge performs the augment merge operation
func (a *augmentMerge) merge() error {
	log := logger.FromContext(*a.settings.Ctx)
	
	log.Debug("Starting CycloneDX augment merge")
	
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
	
	// Build index from primary SBOM components
	if err := a.buildPrimaryIndex(); err != nil {
		return fmt.Errorf("failed to build component index: %w", err)
	}
	
	log.Debugf("Processing %d secondary SBOMs", len(a.secondary))
	
	// Process each secondary SBOM
	for i, sbom := range a.secondary {
		log.Debugf("Processing secondary SBOM %d", i+1)
		if err := a.processSecondaryBom(sbom); err != nil {
			return fmt.Errorf("failed to process secondary SBOM %d: %w", i+1, err)
		}
	}
	
	// Update metadata
	a.updateMetadata()
	
	// Write the merged SBOM
	return a.writeSBOM()
}

// loadPrimaryBom loads the primary SBOM from file
func (a *augmentMerge) loadPrimaryBom() error {
	log := logger.FromContext(*a.settings.Ctx)
	
	primaryPath := a.settings.Assemble.PrimaryFile
	log.Debugf("Loading primary SBOM from %s", primaryPath)
	
	bom, err := loadBom(*a.settings.Ctx, primaryPath)
	if err != nil {
		return err
	}
	
	a.primary = bom
	return nil
}

// loadSecondaryBoms loads all secondary SBOMs
func (a *augmentMerge) loadSecondaryBoms() error {
	log := logger.FromContext(*a.settings.Ctx)
	
	for _, path := range a.settings.Input.Files {
		log.Debugf("Loading secondary SBOM from %s", path)
		bom, err := loadBom(*a.settings.Ctx, path)
		if err != nil {
			return err
		}
		a.secondary = append(a.secondary, bom)
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

// buildPrimaryIndex builds an index of primary SBOM components
func (a *augmentMerge) buildPrimaryIndex() error {
	log := logger.FromContext(*a.settings.Ctx)
	
	components := []matcher.Component{}
	
	// Add primary component if it exists
	if a.primary.Metadata != nil && a.primary.Metadata.Component != nil {
		components = append(components, matcher.NewCDXComponent(a.primary.Metadata.Component))
	}
	
	// Add all components
	if a.primary.Components != nil {
		for i := range *a.primary.Components {
			comp := &(*a.primary.Components)[i]
			components = append(components, matcher.NewCDXComponent(comp))
		}
	}
	
	log.Debugf("Building index with %d components from primary SBOM", len(components))
	a.index = matcher.BuildIndex(components)
	
	return nil
}

// processSecondaryBom processes a single secondary SBOM
func (a *augmentMerge) processSecondaryBom(sbom *cydx.BOM) error {
	log := logger.FromContext(*a.settings.Ctx)
	
	if sbom.Components == nil {
		return nil
	}
	
	newComponents := []cydx.Component{}
	matchedCount := 0
	addedCount := 0
	
	for _, comp := range *sbom.Components {
		unifiedComp := matcher.NewCDXComponent(&comp)
		
		// Find matching component in primary
		matchResult := a.index.FindBestMatch(unifiedComp, a.matcher)
		
		if matchResult != nil {
			// Component exists in primary, merge it
			log.Debugf("Found match for component %s with confidence %d", comp.Name, matchResult.Confidence)
			primaryComp := matchResult.Primary.GetOriginal().(*cydx.Component)
			a.mergeComponent(primaryComp, &comp)
			matchedCount++
		} else {
			// Component doesn't exist, add it
			log.Debugf("No match found for component %s, adding as new", comp.Name)
			newComponents = append(newComponents, comp)
			addedCount++
		}
	}
	
	// Add new components to primary SBOM
	if len(newComponents) > 0 {
		if a.primary.Components == nil {
			a.primary.Components = &[]cydx.Component{}
		}
		*a.primary.Components = append(*a.primary.Components, newComponents...)
		
		// Update index with new components
		for i := range newComponents {
			a.index.AddComponent(matcher.NewCDXComponent(&newComponents[i]))
		}
	}
	
	// Merge dependencies
	a.mergeDependencies(sbom)
	
	log.Debugf("Processed secondary SBOM: %d matched, %d added", matchedCount, addedCount)
	
	return nil
}

// mergeComponent merges fields from secondary component into primary
func (a *augmentMerge) mergeComponent(primary, secondary *cydx.Component) {
	mergeMode := a.settings.Assemble.MergeMode
	
	if mergeMode == "overwrite" {
		a.overwriteComponentFields(primary, secondary)
	} else {
		// Default: if-missing-or-empty
		a.fillMissingComponentFields(primary, secondary)
	}
}

// fillMissingComponentFields fills only missing/empty fields in primary
func (a *augmentMerge) fillMissingComponentFields(primary, secondary *cydx.Component) {
	// Basic fields
	if primary.Description == "" && secondary.Description != "" {
		primary.Description = secondary.Description
	}
	
	if primary.Author == "" && secondary.Author != "" {
		primary.Author = secondary.Author
	}
	
	if primary.Publisher == "" && secondary.Publisher != "" {
		primary.Publisher = secondary.Publisher
	}
	
	if primary.Group == "" && secondary.Group != "" {
		primary.Group = secondary.Group
	}
	
	if primary.Scope == "" && secondary.Scope != "" {
		primary.Scope = secondary.Scope
	}
	
	if primary.Copyright == "" && secondary.Copyright != "" {
		primary.Copyright = secondary.Copyright
	}
	
	// Identifiers
	if primary.PackageURL == "" && secondary.PackageURL != "" {
		primary.PackageURL = secondary.PackageURL
	}
	
	if primary.CPE == "" && secondary.CPE != "" {
		primary.CPE = secondary.CPE
	}
	
	// Supplier
	if primary.Supplier == nil && secondary.Supplier != nil {
		primary.Supplier = secondary.Supplier
	}
	
	// Licenses
	if (primary.Licenses == nil || len(*primary.Licenses) == 0) && secondary.Licenses != nil {
		primary.Licenses = secondary.Licenses
	}
	
	// Hashes
	if (primary.Hashes == nil || len(*primary.Hashes) == 0) && secondary.Hashes != nil {
		primary.Hashes = secondary.Hashes
	}
	
	// External references
	if (primary.ExternalReferences == nil || len(*primary.ExternalReferences) == 0) && secondary.ExternalReferences != nil {
		primary.ExternalReferences = secondary.ExternalReferences
	}
	
	// Properties
	if (primary.Properties == nil || len(*primary.Properties) == 0) && secondary.Properties != nil {
		primary.Properties = secondary.Properties
	}
}

// overwriteComponentFields overwrites primary fields with secondary values
func (a *augmentMerge) overwriteComponentFields(primary, secondary *cydx.Component) {
	// Basic fields
	if secondary.Description != "" {
		primary.Description = secondary.Description
	}
	
	if secondary.Author != "" {
		primary.Author = secondary.Author
	}
	
	if secondary.Publisher != "" {
		primary.Publisher = secondary.Publisher
	}
	
	if secondary.Group != "" {
		primary.Group = secondary.Group
	}
	
	if secondary.Scope != "" {
		primary.Scope = secondary.Scope
	}
	
	if secondary.Copyright != "" {
		primary.Copyright = secondary.Copyright
	}
	
	// Identifiers
	if secondary.PackageURL != "" {
		primary.PackageURL = secondary.PackageURL
	}
	
	if secondary.CPE != "" {
		primary.CPE = secondary.CPE
	}
	
	// Supplier
	if secondary.Supplier != nil {
		primary.Supplier = secondary.Supplier
	}
	
	// Licenses
	if secondary.Licenses != nil && len(*secondary.Licenses) > 0 {
		primary.Licenses = secondary.Licenses
	}
	
	// Hashes
	if secondary.Hashes != nil && len(*secondary.Hashes) > 0 {
		primary.Hashes = secondary.Hashes
	}
	
	// External references
	if secondary.ExternalReferences != nil && len(*secondary.ExternalReferences) > 0 {
		primary.ExternalReferences = secondary.ExternalReferences
	}
	
	// Properties
	if secondary.Properties != nil && len(*secondary.Properties) > 0 {
		primary.Properties = secondary.Properties
	}
}

// mergeDependencies merges dependency relationships from secondary SBOM
func (a *augmentMerge) mergeDependencies(sbom *cydx.BOM) {
	if sbom.Dependencies == nil || len(*sbom.Dependencies) == 0 {
		return
	}
	
	log := logger.FromContext(*a.settings.Ctx)
	
	// Create dependency map for efficient lookup
	depMap := make(map[string]*cydx.Dependency)
	if a.primary.Dependencies != nil {
		for i := range *a.primary.Dependencies {
			dep := &(*a.primary.Dependencies)[i]
			depMap[dep.Ref] = dep
		}
	} else {
		a.primary.Dependencies = &[]cydx.Dependency{}
	}
	
	// Merge dependencies from secondary
	for _, secDep := range *sbom.Dependencies {
		if existingDep, exists := depMap[secDep.Ref]; exists {
			// Merge dependency lists
			if secDep.Dependencies != nil && len(*secDep.Dependencies) > 0 {
				existingDeps := lo.FromPtr(existingDep.Dependencies)
				newDeps := lo.FromPtr(secDep.Dependencies)
				merged := lo.Uniq(append(existingDeps, newDeps...))
				existingDep.Dependencies = &merged
			}
		} else {
			// Add new dependency
			*a.primary.Dependencies = append(*a.primary.Dependencies, secDep)
			depMap[secDep.Ref] = &secDep
		}
	}
	
	log.Debugf("Merged dependencies, total: %d", len(*a.primary.Dependencies))
}

// updateMetadata updates the primary SBOM metadata
func (a *augmentMerge) updateMetadata() {
	log := logger.FromContext(*a.settings.Ctx)
	
	if a.primary.Metadata == nil {
		a.primary.Metadata = &cydx.Metadata{}
	}
	
	// Update timestamp
	a.primary.Metadata.Timestamp = utcNowTime()
	
	// Add tool information
	if a.primary.Metadata.Tools == nil {
		a.primary.Metadata.Tools = &cydx.ToolsChoice{}
		a.primary.Metadata.Tools.Components = &[]cydx.Component{}
	}
	
	// Add sbomasm as a tool
	sbomasmTool := cydx.Component{
		Type:    cydx.ComponentTypeApplication,
		Name:    "sbomasm",
		Version: version.GetVersionInfo().GitVersion,
		Author:  "Interlynk.io",
	}
	
	*a.primary.Metadata.Tools.Components = append(*a.primary.Metadata.Tools.Components, sbomasmTool)
	
	log.Debug("Updated metadata with timestamp and tool information")
}

// writeSBOM writes the augmented SBOM to output
func (a *augmentMerge) writeSBOM() error {
	log := logger.FromContext(*a.settings.Ctx)
	
	outputPath := a.settings.Output.File
	format := a.settings.Output.FileFormat
	specVersion := a.settings.Output.SpecVersion
	
	log.Debugf("Writing augmented SBOM to %s in %s format", outputPath, format)
	
	// Set spec version
	if specVersion != "" {
		if sv, ok := specVersionMap[specVersion]; ok {
			a.primary.SpecVersion = sv
		}
	}
	
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
	
	// Encode based on format
	if format == "xml" {
		encoder := cydx.NewBOMEncoder(writer, cydx.BOMFileFormatXML)
		encoder.SetPretty(true)
		return encoder.Encode(a.primary)
	} else {
		// Default to JSON
		encoder := cydx.NewBOMEncoder(writer, cydx.BOMFileFormatJSON)
		encoder.SetPretty(true)
		encoder.SetEscapeHTML(false)
		return encoder.Encode(a.primary)
	}
}