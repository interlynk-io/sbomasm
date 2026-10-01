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

package spdx3

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/interlynk-io/sbomasm/v2/pkg/assemble/matcher"
	"github.com/interlynk-io/sbomasm/v2/pkg/logger"
	"github.com/interlynk-io/sbomasm/v2/pkg/sbom"
	spdx3model "github.com/interlynk-io/spdx-zen/model/v3.0.1"
	"github.com/interlynk-io/spdx-zen/parse"
	"sigs.k8s.io/release-utils/version"
)

// ---------------------------------------------------------------------------
// SPDX 3.0 Component Wrapper for Matcher
// ---------------------------------------------------------------------------

// spdx3PackageComponent wraps an SPDX 3.0 Package to implement matcher.Component.
type spdx3PackageComponent struct {
	pkg *spdx3model.Package
}

func newSpdx3PackageComponent(pkg *spdx3model.Package) matcher.Component {
	return &spdx3PackageComponent{pkg: pkg}
}

func (c *spdx3PackageComponent) GetPurl() string {
	if c.pkg == nil {
		return ""
	}
	for _, id := range c.pkg.ExternalIdentifier {
		if id.ExternalIdentifierType == spdx3model.ExternalIdentifierTypePackageUrl {
			return id.Identifier
		}
	}
	return ""
}

func (c *spdx3PackageComponent) GetCPE() string {
	if c.pkg == nil {
		return ""
	}
	for _, id := range c.pkg.ExternalIdentifier {
		if id.ExternalIdentifierType == spdx3model.ExternalIdentifierTypeCpe22 ||
			id.ExternalIdentifierType == spdx3model.ExternalIdentifierTypeCpe23 {
			return id.Identifier
		}
	}
	return ""
}

func (c *spdx3PackageComponent) GetName() string {
	if c.pkg == nil {
		return ""
	}
	return c.pkg.Name
}

func (c *spdx3PackageComponent) GetVersion() string {
	if c.pkg == nil {
		return ""
	}
	return c.pkg.PackageVersion
}

func (c *spdx3PackageComponent) GetType() string {
	if c.pkg == nil {
		return ""
	}
	return string(c.pkg.PrimaryPurpose)
}

func (c *spdx3PackageComponent) IsCDX() bool  { return false }
func (c *spdx3PackageComponent) IsSPDX() bool { return false }

func (c *spdx3PackageComponent) GetOriginal() interface{} {
	return c.pkg
}

// ---------------------------------------------------------------------------
// Augment Merge
// ---------------------------------------------------------------------------

type augmentMerge struct {
	settings      *MergeSettings
	primary       *parse.Document
	secondary     []*parse.Document
	matcher       matcher.ComponentMatcher
	index         *matcher.ComponentIndex
	processedPkgs map[string]string // secondary SpdxID -> primary SpdxID
	addedPkgIDs   map[string]bool   // newly added package SpdxIDs
}

func newAugmentMerge(ms *MergeSettings) *augmentMerge {
	return &augmentMerge{
		settings:      ms,
		secondary:     []*parse.Document{},
		processedPkgs: make(map[string]string),
		addedPkgIDs:   make(map[string]bool),
	}
}

func (a *augmentMerge) merge() error {
	log := logger.FromContext(*a.settings.Ctx)
	log.Debug("Starting SPDX 3.0 augment merge")

	if err := a.loadPrimaryBom(); err != nil {
		return fmt.Errorf("failed to load primary SBOM: %w", err)
	}

	if err := a.loadSecondaryBoms(); err != nil {
		return fmt.Errorf("failed to load secondary SBOMs: %w", err)
	}

	if err := a.setupMatcher(); err != nil {
		return fmt.Errorf("failed to setup matcher: %w", err)
	}

	if err := a.buildPrimaryIndex(); err != nil {
		return fmt.Errorf("failed to build package index: %w", err)
	}

	log.Debugf("Processing %d secondary SBOMs", len(a.secondary))

	for i, doc := range a.secondary {
		log.Debugf("Processing secondary SBOM %d", i+1)
		a.processedPkgs = make(map[string]string)
		a.addedPkgIDs = make(map[string]bool)
		if err := a.processSecondaryBom(doc); err != nil {
			return fmt.Errorf("failed to process secondary SBOM %d: %w", i+1, err)
		}
	}

	a.updateCreationInfo()

	return a.writeSBOM()
}

// loadPrimaryBom loads the primary SBOM from the --primary file.
func (a *augmentMerge) loadPrimaryBom() error {
	log := logger.FromContext(*a.settings.Ctx)
	primaryPath := a.settings.Assemble.PrimaryFile
	log.Debugf("Loading primary SBOM from %s", primaryPath)

	sbomDoc, err := sbom.Parser(*a.settings.Ctx, primaryPath)
	if err != nil {
		return err
	}

	spdx3Doc, ok := sbomDoc.(*sbom.SPDX3Document)
	if !ok {
		return fmt.Errorf("expected SPDX 3.0 document, got %T", sbomDoc)
	}

	a.primary = spdx3Doc.Doc
	return nil
}

// loadSecondaryBoms loads all secondary SBOMs from input files.
func (a *augmentMerge) loadSecondaryBoms() error {
	log := logger.FromContext(*a.settings.Ctx)

	for _, path := range a.settings.Input.Files {
		log.Debugf("Loading secondary SBOM from %s", path)
		sbomDoc, err := sbom.Parser(*a.settings.Ctx, path)
		if err != nil {
			return err
		}
		spdx3Doc, ok := sbomDoc.(*sbom.SPDX3Document)
		if !ok {
			return fmt.Errorf("expected SPDX 3.0 document, got %T", sbomDoc)
		}
		a.secondary = append(a.secondary, spdx3Doc.Doc)
	}

	return nil
}

// setupMatcher creates the composite component matcher.
func (a *augmentMerge) setupMatcher() error {
	factory := matcher.NewDefaultMatcherFactory(&matcher.MatcherConfig{
		Strategy:      "composite",
		StrictVersion: false,
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

// buildPrimaryIndex builds an index of primary SBOM packages.
func (a *augmentMerge) buildPrimaryIndex() error {
	log := logger.FromContext(*a.settings.Ctx)

	components := []matcher.Component{}
	for _, pkg := range a.primary.Packages {
		if pkg != nil {
			components = append(components, newSpdx3PackageComponent(pkg))
		}
	}

	log.Debugf("Building index with %d packages from primary SBOM", len(components))
	a.index = matcher.BuildIndex(components)
	return nil
}

// processSecondaryBom processes a single secondary SBOM.
func (a *augmentMerge) processSecondaryBom(doc *parse.Document) error {
	log := logger.FromContext(*a.settings.Ctx)

	if len(doc.Packages) == 0 {
		return nil
	}

	newPackages := []*spdx3model.Package{}
	matchedCount := 0
	addedCount := 0

	for _, pkg := range doc.Packages {
		if pkg == nil {
			continue
		}

		unifiedPkg := newSpdx3PackageComponent(pkg)
		matchResult := a.index.FindBestMatch(unifiedPkg, a.matcher)

		if matchResult != nil {
			// Package exists in primary — merge it
			log.Debugf("Found match for package %s with confidence %d", pkg.Name, matchResult.Confidence)
			primaryPkg := matchResult.Primary.GetOriginal().(*spdx3model.Package)
			a.mergePackage(primaryPkg, pkg)
			a.processedPkgs[pkg.SpdxID] = primaryPkg.SpdxID
			matchedCount++
		} else {
			// Package doesn't exist — clone and add with rewritten SpdxID
			log.Debugf("No match found for package %s, adding as new", pkg.Name)
			clone := &spdx3model.Package{}
			if err := cloneElement(pkg, clone); err != nil {
				log.Warnf("failed to clone package %s: %v", pkg.Name, err)
				continue
			}
			clone.SpdxID = fmt.Sprintf("https://interlynk.io/package/%s-%s-%s",
				sanitizeForID(clone.Name), sanitizeForID(clone.PackageVersion), uuid.New().String())

			newPackages = append(newPackages, clone)
			a.addedPkgIDs[clone.SpdxID] = true
			a.processedPkgs[pkg.SpdxID] = clone.SpdxID
			addedCount++
		}
	}

	// Add new packages to primary
	if len(newPackages) > 0 {
		a.primary.Packages = append(a.primary.Packages, newPackages...)
		for _, pkg := range newPackages {
			a.index.AddComponent(newSpdx3PackageComponent(pkg))
		}
	}

	// Merge relationships for processed packages only
	a.mergeSelectiveRelationships(doc)

	log.Debugf("Processed secondary SBOM: %d matched, %d added", matchedCount, addedCount)
	return nil
}

// mergePackage merges fields from secondary into primary based on merge mode.
func (a *augmentMerge) mergePackage(primary, secondary *spdx3model.Package) {
	if a.settings.Assemble.MergeMode == "overwrite" {
		a.overwritePackageFields(primary, secondary)
	} else {
		a.fillMissingPackageFields(primary, secondary)
	}
}

// fillMissingPackageFields fills only missing/empty fields in primary.
func (a *augmentMerge) fillMissingPackageFields(primary, secondary *spdx3model.Package) {
	if primary.Description == "" && secondary.Description != "" {
		primary.Description = secondary.Description
	}
	if primary.CopyrightText == "" && secondary.CopyrightText != "" {
		primary.CopyrightText = secondary.CopyrightText
	}
	if primary.DownloadLocation == "" && secondary.DownloadLocation != "" {
		primary.DownloadLocation = secondary.DownloadLocation
	}
	if primary.HomePage == "" && secondary.HomePage != "" {
		primary.HomePage = secondary.HomePage
	}
	// Supplier (SuppliedBy)
	if primary.SuppliedBy == nil && secondary.SuppliedBy != nil {
		primary.SuppliedBy = secondary.SuppliedBy
	}

	// Hashes (VerifiedUsing)
	if len(primary.VerifiedUsing) == 0 && len(secondary.VerifiedUsing) > 0 {
		primary.VerifiedUsing = secondary.VerifiedUsing
	} else if len(secondary.VerifiedUsing) > 0 {
		existing := make(map[string]bool)
		for _, h := range primary.VerifiedUsing {
			if hash, ok := h.(spdx3model.Hash); ok {
				key := fmt.Sprintf("%s:%s", hash.Algorithm, hash.HashValue)
				existing[key] = true
			}
		}
		for _, h := range secondary.VerifiedUsing {
			if hash, ok := h.(spdx3model.Hash); ok {
				key := fmt.Sprintf("%s:%s", hash.Algorithm, hash.HashValue)
				if !existing[key] {
					primary.VerifiedUsing = append(primary.VerifiedUsing, h)
					existing[key] = true
				}
			}
		}
	}

	// External identifiers (purl, cpe, etc.)
	if len(primary.ExternalIdentifier) == 0 && len(secondary.ExternalIdentifier) > 0 {
		primary.ExternalIdentifier = secondary.ExternalIdentifier
	} else if len(secondary.ExternalIdentifier) > 0 {
		existing := make(map[string]bool)
		for _, id := range primary.ExternalIdentifier {
			key := fmt.Sprintf("%s:%s", id.ExternalIdentifierType, id.Identifier)
			existing[key] = true
		}
		for _, id := range secondary.ExternalIdentifier {
			key := fmt.Sprintf("%s:%s", id.ExternalIdentifierType, id.Identifier)
			if !existing[key] {
				primary.ExternalIdentifier = append(primary.ExternalIdentifier, id)
				existing[key] = true
			}
		}
	}

	// Primary purpose
	if primary.PrimaryPurpose == "" && secondary.PrimaryPurpose != "" {
		primary.PrimaryPurpose = secondary.PrimaryPurpose
	}
}

// overwritePackageFields overwrites primary fields with secondary values.
func (a *augmentMerge) overwritePackageFields(primary, secondary *spdx3model.Package) {
	if secondary.Description != "" {
		primary.Description = secondary.Description
	}
	if secondary.CopyrightText != "" {
		primary.CopyrightText = secondary.CopyrightText
	}
	if secondary.DownloadLocation != "" {
		primary.DownloadLocation = secondary.DownloadLocation
	}
	if secondary.HomePage != "" {
		primary.HomePage = secondary.HomePage
	}
	if secondary.SuppliedBy != nil {
		primary.SuppliedBy = secondary.SuppliedBy
	}
	if len(secondary.VerifiedUsing) > 0 {
		primary.VerifiedUsing = secondary.VerifiedUsing
	}
	if len(secondary.ExternalIdentifier) > 0 {
		primary.ExternalIdentifier = secondary.ExternalIdentifier
	}
	if secondary.PrimaryPurpose != "" {
		primary.PrimaryPurpose = secondary.PrimaryPurpose
	}
}

// mergeSelectiveRelationships merges only relationships involving processed packages.
func (a *augmentMerge) mergeSelectiveRelationships(doc *parse.Document) {
	if len(doc.Relationships) == 0 {
		return
	}

	log := logger.FromContext(*a.settings.Ctx)
	validIDs := a.buildValidIDSet()

	// Build dedup map from primary relationships
	relMap := make(map[string]bool)
	for _, rel := range a.primary.Relationships {
		if rel == nil {
			continue
		}
		key := fmt.Sprintf("%s:%s:%s", rel.From.SpdxID, rel.RelationshipType, elementsKey(rel.To))
		relMap[key] = true
	}

	addedCount := 0
	skippedCount := 0

	for _, rel := range doc.Relationships {
		if rel == nil {
			continue
		}

		// Skip DESCRIBES from secondary SBOMs
		if rel.RelationshipType == spdx3model.RelationshipTypeDescribes {
			skippedCount++
			continue
		}

		if !a.isRelationshipRelevant(rel) {
			skippedCount++
			continue
		}

		// Resolve From/To IDs
		resolvedFrom := a.resolveSpdxID(rel.From.SpdxID)
		resolvedTo := []spdx3model.Element{}
		for _, to := range rel.To {
			resolvedTo = append(resolvedTo, spdx3model.Element{SpdxID: a.resolveSpdxID(to.SpdxID)})
		}

		// Validate IDs exist in primary
		if !validIDs[resolvedFrom] {
			log.Debugf("Skipping relationship: resolved From %s not in primary", resolvedFrom)
			skippedCount++
			continue
		}
		validTo := true
		for _, to := range resolvedTo {
			if !validIDs[to.SpdxID] {
				validTo = false
				break
			}
		}
		if !validTo {
			log.Debugf("Skipping relationship: resolved To not in primary")
			skippedCount++
			continue
		}

		// Clone relationship with resolved IDs
		newRel := &spdx3model.Relationship{}
		if err := cloneElement(rel, newRel); err != nil {
			continue
		}
		newRel.From.SpdxID = resolvedFrom
		newRel.To = resolvedTo
		newRel.SpdxID = fmt.Sprintf("https://interlynk.io/relationship/%s-%s-%s",
			string(newRel.RelationshipType), sanitizeForID(resolvedFrom), uuid.New().String())

		// Deduplicate
		dedupKey := fmt.Sprintf("%s:%s:%s", newRel.From.SpdxID, newRel.RelationshipType, elementsKey(newRel.To))
		if !relMap[dedupKey] {
			a.primary.Relationships = append(a.primary.Relationships, newRel)
			relMap[dedupKey] = true
			addedCount++
		}
	}

	log.Debugf("Merged relationships: added %d, skipped %d, total: %d",
		addedCount, skippedCount, len(a.primary.Relationships))
}

// buildValidIDSet returns all valid SpdxIDs in the primary SBOM.
func (a *augmentMerge) buildValidIDSet() map[string]bool {
	valid := make(map[string]bool)

	if a.primary.SpdxDocument != nil {
		valid[a.primary.SpdxDocument.SpdxID] = true
	}
	for _, pkg := range a.primary.Packages {
		if pkg != nil {
			valid[pkg.SpdxID] = true
		}
	}
	for _, file := range a.primary.Files {
		if file != nil {
			valid[file.SpdxID] = true
		}
	}
	for _, org := range a.primary.Organizations {
		if org != nil {
			valid[org.SpdxID] = true
		}
	}
	for _, person := range a.primary.Persons {
		if person != nil {
			valid[person.SpdxID] = true
		}
	}
	for _, tool := range a.primary.Tools {
		if tool != nil {
			valid[tool.SpdxID] = true
		}
	}
	return valid
}

// isRelationshipRelevant checks if either end of a relationship is a processed package.
func (a *augmentMerge) isRelationshipRelevant(rel *spdx3model.Relationship) bool {
	_, fromProcessed := a.processedPkgs[rel.From.SpdxID]
	if fromProcessed {
		return true
	}
	for _, to := range rel.To {
		if _, toProcessed := a.processedPkgs[to.SpdxID]; toProcessed {
			return true
		}
	}
	return false
}

// resolveSpdxID maps a secondary SpdxID to its primary equivalent.
func (a *augmentMerge) resolveSpdxID(id string) string {
	if mapped, exists := a.processedPkgs[id]; exists {
		return mapped
	}
	return id
}

// updateCreationInfo updates the primary SBOM's CreationInfo.
func (a *augmentMerge) updateCreationInfo() {
	log := logger.FromContext(*a.settings.Ctx)

	if a.primary.SpdxDocument == nil {
		return
	}

	ci := &a.primary.SpdxDocument.CreationInfo
	if ci == nil {
		return
	}

	// Update timestamp
	ci.Created = time.Now().UTC()

	// Add sbomasm tool to CreatedUsing
	tool := spdx3model.Tool{
		Element: spdx3model.Element{
			SpdxID: fmt.Sprintf("https://interlynk.io/tool/sbomasm-%s", version.GetVersionInfo().GitVersion),
			Name:   "sbomasm",
		},
	}

	found := false
	for _, t := range ci.CreatedUsing {
		if t.Name == tool.Name {
			found = true
			break
		}
	}
	if !found {
		ci.CreatedUsing = append(ci.CreatedUsing, tool)
	}

	// Add sbomasm as creator agent
	sbomasmAgent := spdx3model.Agent{Element: tool.Element}
	foundAgent := false
	for _, agent := range ci.CreatedBy {
		if agent.Name == sbomasmAgent.Name {
			foundAgent = true
			break
		}
	}
	if !foundAgent {
		ci.CreatedBy = append(ci.CreatedBy, sbomasmAgent)
	}

	// Update comment
	var docNames []string
	for _, doc := range a.secondary {
		if doc.SpdxDocument != nil {
			docNames = append(docNames, doc.SpdxDocument.Name)
		}
	}
	if len(docNames) > 0 {
		ci.Comment = fmt.Sprintf("Augmented by sbomasm (%s) using %s",
			version.GetVersionInfo().GitVersion, strings.Join(docNames, ", "))
	}

	log.Debug("Updated creation info with timestamp and tool information")
}

// writeSBOM writes the augmented SBOM to output.
func (a *augmentMerge) writeSBOM() error {
	log := logger.FromContext(*a.settings.Ctx)
	outputPath := a.settings.Output.File

	log.Debugf("Writing augmented SBOM to %s", outputPath)

	var w io.Writer
	if outputPath == "" {
		w = os.Stdout
	} else {
		file, err := os.Create(outputPath)
		if err != nil {
			return fmt.Errorf("failed to create output file: %w", err)
		}
		defer file.Close()
		w = file
	}

	wrapper := &sbom.SPDX3Document{Doc: a.primary}
	if err := sbom.WriteSBOM(w, wrapper); err != nil {
		return fmt.Errorf("failed to write SPDX 3.0 SBOM: %w", err)
	}

	return nil
}
