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
	"context"
	"strings"

	cydx "github.com/CycloneDX/cyclonedx-go"
	"github.com/interlynk-io/sbomasm/v2/pkg/logger"
	"github.com/interlynk-io/sbomasm/v2/pkg/rm/types"
)

func RemoveSupplierFromMetadata(c context.Context, bom *cydx.BOM, targets []interface{}) error {
	log := logger.FromContext(c)
	if bom.Metadata == nil || bom.Metadata.Supplier == nil {
		return nil
	}

	original := bom.Metadata.Supplier
	removed := false

	for _, tar := range targets {
		candidate, ok := tar.(cydx.OrganizationalEntity)
		if !ok {
			continue
		}
		if matchSupplier(*original, candidate) {
			bom.Metadata.Supplier = nil
			removed = true
			break
		}
	}

	if removed {
		log.Debugf("Removed 1 supplier from metadata.")
	}
	return nil
}

func matchSupplier(a, b cydx.OrganizationalEntity) bool {
	if a.Name != "" && a.Name == b.Name {
		return true
	}

	// Optional: Add more strict matching on contact or URL
	if a.URL != nil && b.URL != nil && len(*a.URL) > 0 && len(*b.URL) > 0 && (*a.URL)[0] == (*b.URL)[0] {
		return true
	}

	return false
}

func RemoveLicenseFromMetadata(c context.Context, bom *cydx.BOM, targets []interface{}) error {
	log := logger.FromContext(c)
	if bom.Metadata == nil || bom.Metadata.Licenses == nil {
		return nil
	}

	originalCount := len(*bom.Metadata.Licenses)
	var filtered cydx.Licenses

	for _, lic := range *bom.Metadata.Licenses {
		match := false
		for _, tar := range targets {
			if matchLicense(tar, lic) {
				match = true
				break
			}
		}
		if !match {
			filtered = append(filtered, lic)
		}
	}

	removedCount := originalCount - len(filtered)

	if len(filtered) == 0 {
		bom.Metadata.Licenses = nil
	} else {
		bom.Metadata.Licenses = &filtered
	}
	log.Debugf("Removed %d license(s) from metadata.\n", removedCount)

	return nil
}

func matchLicense(tar interface{}, lic cydx.LicenseChoice) bool {
	candidate, ok := tar.(cydx.LicenseChoice)
	if !ok {
		return false
	}

	// Expression match
	if candidate.Expression != "" && candidate.Expression == lic.Expression {
		return true
	}

	// License object match (ID or Name)
	if candidate.License != nil && lic.License != nil {
		if candidate.License.ID != "" && candidate.License.ID == lic.License.ID {
			return true
		}
		if candidate.License.Name != "" && candidate.License.Name == lic.License.Name {
			return true
		}
	}

	return false
}

func RemoveAuthorFromMetadata(c context.Context, bom *cydx.BOM, targets []interface{}) error {
	log := logger.FromContext(c)
	if bom.Metadata == nil || bom.Metadata.Authors == nil {
		return nil
	}

	var filtered []cydx.OrganizationalContact
	original := *bom.Metadata.Authors

	for _, author := range original {
		if !isAuthorInTargets(author, targets) {
			filtered = append(filtered, author)
		}
	}

	// Optional: log change
	removedCount := len(original) - len(filtered)

	if len(filtered) == 0 {
		bom.Metadata.Authors = nil
	} else {
		bom.Metadata.Authors = &filtered
	}
	log.Debugf("Removed %d author(s) from metadata.\n", removedCount)
	return nil
}

func isAuthorInTargets(author cydx.OrganizationalContact, targets []interface{}) bool {
	for _, tar := range targets {
		if candidate, ok := tar.(cydx.OrganizationalContact); ok {
			if candidate.Name == author.Name && candidate.Email == author.Email {
				return true
			}
		}
	}
	return false
}

func RemoveLifecycleFromMetadata(c context.Context, bom *cydx.BOM, targets []interface{}) error {
	log := logger.FromContext(c)
	if bom.Metadata == nil || bom.Metadata.Lifecycles == nil {
		return nil
	}

	var filtered []cydx.Lifecycle
	original := *bom.Metadata.Lifecycles

	for _, lifecycle := range original {
		if !isLifecycleInTargets(lifecycle, targets) {
			filtered = append(filtered, lifecycle)
		}
	}

	removedCount := len(original) - len(filtered)
	log.Debugf("Removed %d lifecycle(s) from metadata.\n", removedCount)

	if len(filtered) == 0 {
		bom.Metadata.Lifecycles = nil
	} else {
		bom.Metadata.Lifecycles = &filtered
	}

	return nil
}

func isLifecycleInTargets(candidate cydx.Lifecycle, targets []interface{}) bool {
	for _, target := range targets {
		if target == string(candidate.Phase) {
			return true
		}
	}
	return false
}

func RemoveRepositoryFromMetadata(ctx context.Context, bom *cydx.BOM, targets []interface{}) error {
	log := logger.FromContext(ctx)
	if bom.Metadata == nil || bom.ExternalReferences == nil {
		return nil
	}

	var (
		filtered []cydx.ExternalReference
		removed  int
	)

	for _, ref := range *bom.ExternalReferences {
		if strings.ToLower(string(ref.Type)) != "vcs" {
			filtered = append(filtered, ref)
			continue
		}

		match := false
		for _, target := range targets {
			candidate, ok := target.(cydx.ExternalReference)
			if ok && matchExternalReference(candidate, ref) {
				match = true
				break
			}
		}

		if match {
			removed++
			continue // skip adding this ref
		}
		filtered = append(filtered, ref)
	}

	if len(filtered) == 0 {
		bom.ExternalReferences = nil
	} else {
		bom.ExternalReferences = &filtered
	}

	log.Debugf("Removed %d repository (VCS) reference(s) from metadata.\n", removed)
	return nil
}

func matchExternalReference(a, b cydx.ExternalReference) bool {
	return a.Type == b.Type && a.URL == b.URL && a.Comment == b.Comment
}

func RemoveTimestampFromMetadata(ctx context.Context, bom *cydx.BOM, targets []interface{}) error {
	log := logger.FromContext(ctx)
	if bom.Metadata == nil {
		return nil
	}
	bom.Metadata.Timestamp = ""
	log.Debugf("Removed timestamp from metadata.")
	return nil
}

func RemoveToolFromMetadata(ctx context.Context, bom *cydx.BOM, targets []interface{}) error {
	log := logger.FromContext(ctx)
	if bom.Metadata == nil || bom.Metadata.Tools == nil {
		return nil
	}

	removedCount := 0

	matchToolByNameAndVersion := func(aName, aVersion, bName, bVersion string) bool {
		return aName == bName && aVersion == bVersion
	}

	if bom.Metadata.Tools.Components != nil {
		var filtered []cydx.Component
		for _, tool := range *bom.Metadata.Tools.Components {
			match := false
			for _, tar := range targets {
				if candidate, ok := tar.(cydx.Component); ok {
					if matchToolByNameAndVersion(tool.Name, tool.Version, candidate.Name, candidate.Version) {
						match = true
						break
					}
				}
			}
			if match {
				removedCount++
			} else {
				filtered = append(filtered, tool)
			}
		}
		bom.Metadata.Tools.Components = &filtered
	}

	if bom.Metadata.Tools.Tools != nil {
		var filtered []cydx.Tool
		for _, tool := range *bom.Metadata.Tools.Tools {
			match := false
			for _, tar := range targets {
				if candidate, ok := tar.(cydx.Tool); ok {
					if matchToolByNameAndVersion(tool.Name, tool.Version, candidate.Name, candidate.Version) {
						match = true
						break
					}
				}
			}
			if match {
				removedCount++
			} else {
				filtered = append(filtered, tool)
			}
		}
		bom.Metadata.Tools.Tools = &filtered
	}

	if (bom.Metadata.Tools.Tools == nil || len(*bom.Metadata.Tools.Tools) == 0) &&
		(bom.Metadata.Tools.Components == nil || len(*bom.Metadata.Tools.Components) == 0) {
		bom.Metadata.Tools = nil
	}

	log.Debugf("Removed %d tool(s) from metadata.\n", removedCount)
	return nil
}

func RemoveAuthorFromComponent(doc *cydx.BOM, entries []interface{}, params *types.RmParams) error {
	log := logger.FromContext(*params.Ctx)
	removedCount := 0
	for _, e := range entries {
		entry, ok := e.(AuthorEntry)
		if !ok || entry.Author == nil {
			log.Debugf("Skipping invalid author entry: %v", e)
			continue
		}

		comp := entry.Component
		found := false
		if doc.Metadata.Component != nil && comp == doc.Metadata.Component {
			log.Debugf("Found component in metadata: %s@%s", comp.Name, comp.Version)
			found = true
		} else if doc.Components != nil {
			for i := range *doc.Components {
				if &(*doc.Components)[i] == comp {
					log.Debugf("Found component in components: %s@%s", comp.Name, comp.Version)
					found = true
					break
				}
			}
		}
		if !found {
			log.Debugf("Warning: Component %s@%s not found in document\n", comp.Name, comp.Version)
			continue
		}

		if comp.Authors != nil {
			var newAuthors []cydx.OrganizationalContact
			for _, author := range *comp.Authors {
				if author != *entry.Author {
					newAuthors = append(newAuthors, author)
				}
			}
			comp.Authors = &newAuthors
			if len(newAuthors) == 0 {
				comp.Authors = nil
			}
			removedCount++
			if params.Value == "NOASSERTION" {
				log.Warnf("Warning: NOASSERTION is unlikely for author field")
			}
		}
	}

	log.Debugf("Removed %d author entries from components\n", removedCount)
	if removedCount == 0 {
		log.Debugf("No author entries removed")
	}
	return nil
}

func RemoveSupplierFromComponent(doc *cydx.BOM, entries []interface{}, params *types.RmParams) error {
	log := logger.FromContext(*params.Ctx)
	removedCount := 0
	for _, e := range entries {
		entry, ok := e.(SupplierEntry)
		if !ok || entry.Value == nil {
			log.Debugf("Skipping invalid supplier entry: %v", e)
			continue
		}

		comp := entry.Component
		found := false
		if doc.Metadata.Component != nil && comp == doc.Metadata.Component {
			found = true
		} else if doc.Components != nil {
			for i := range *doc.Components {
				if &(*doc.Components)[i] == comp {
					found = true
					break
				}
			}
		}
		if !found {
			log.Warnf("Warning: Component %s@%s not found in document\n", comp.Name, comp.Version)
			continue
		}

		if comp.Supplier != nil && (strings.Contains(entry.Value.Name, params.Value) || containsURL(entry.Value.URL, params.Value)) {
			comp.Supplier = nil
			removedCount++
			log.Debugf("Removed supplier from component: %s@%s, Supplier: %s\n", comp.Name, comp.Version, entry.Value)
			if params.Value == "NOASSERTION" {
				log.Warnf("Matched NOASSERTION for supplier")
			}
		}
	}

	log.Debugf("Removed %d supplier entries from components\n", removedCount)
	if removedCount == 0 {
		log.Debugf("No supplier entries removed")
	}
	return nil
}

func RemoveCopyrightFromComponent(doc *cydx.BOM, entries []interface{}, params *types.RmParams) error {
	log := logger.FromContext(*params.Ctx)
	removedCount := 0
	for _, e := range entries {
		entry, ok := e.(CopyrightEntry)
		if !ok || entry.Value == "" {
			log.Debugf("Skipping invalid copyright entry: %v", e)
			continue
		}

		comp := entry.Component
		found := false
		if doc.Metadata.Component != nil && comp == doc.Metadata.Component {
			found = true
		} else if doc.Components != nil {
			for i := range *doc.Components {
				if &(*doc.Components)[i] == comp {
					found = true
					break
				}
			}
		}
		if !found {
			log.Warnf("Warning: Component %s@%s not found in document\n", comp.Name, comp.Version)
			continue
		}

		if strings.EqualFold(comp.Copyright, entry.Value) {
			comp.Copyright = ""
			removedCount++
			log.Debugf("Removed copyright from component: %s@%s, Copyright: %s\n", comp.Name, comp.Version, entry.Value)
			if params.Value == "NOASSERTION" {
				log.Warnf("Matched NOASSERTION for copyright")
			}
		}
	}

	log.Debugf("Removed %d copyright entries from components\n", removedCount)
	if removedCount == 0 {
		log.Debugf("No copyright entries removed")
	}
	return nil
}

func RemoveCpeFromComponent(doc *cydx.BOM, entries []interface{}, params *types.RmParams) error {
	log := logger.FromContext(*params.Ctx)
	removedCount := 0
	for _, e := range entries {
		entry, ok := e.(CpeEntry)
		if !ok || entry.Ref == "" {
			log.Debugf("Skipping invalid CPE entry: %v", e)
			continue
		}

		comp := entry.Component
		found := false
		if doc.Metadata.Component != nil && comp == doc.Metadata.Component {
			found = true
		} else if doc.Components != nil {
			for i := range *doc.Components {
				if &(*doc.Components)[i] == comp {
					found = true
					break
				}
			}
		}
		if !found {
			log.Warnf("Warning: Component %s@%s not found in document\n", comp.Name, comp.Version)
			continue
		}

		if comp.CPE != "" {
			if strings.EqualFold(comp.CPE, entry.Ref) {
				comp.CPE = ""
				removedCount++
				log.Debugf("Removed legacy CPE from component: %s@%s, CPE: %s\n", comp.Name, comp.Version, entry.Ref)
				if params.Value == "NOASSERTION" {
					log.Warnf("Warning: NOASSERTION is unlikely for CPE field")
				}
			}
			log.Debugf("New value of comp.CPE: %s\n", comp.CPE)
		}
	}

	log.Debugf("Removed %d CPE entries from components\n", removedCount)
	if removedCount == 0 {
		log.Debugf("No CPE entries removed\n")
	}

	return nil
}

func RemoveDescriptionFromComponent(doc *cydx.BOM, entries []interface{}, params *types.RmParams) error {
	log := logger.FromContext(*params.Ctx)
	removedCount := 0
	for _, e := range entries {
		entry, ok := e.(DescriptionEntry)
		if !ok || entry.Value == "" {
			log.Debugf("Skipping invalid description entry: %v", e)
			continue
		}

		comp := entry.Component
		found := false
		if doc.Metadata.Component != nil && comp == doc.Metadata.Component {
			found = true
		} else if doc.Components != nil {
			for i := range *doc.Components {
				if &(*doc.Components)[i] == comp {
					found = true
					break
				}
			}
		}

		if !found {
			log.Warnf("Warning: Component %s@%s not found in document\n", comp.Name, comp.Version)
			continue
		}

		if comp.Description != "" && strings.EqualFold(comp.Description, entry.Value) {
			comp.Description = ""
			removedCount++
			log.Debugf("Removed description from component: %s@%s, Description: %s\n", comp.Name, comp.Version, entry.Value)
			if params.Value == "NOASSERTION" {
				log.Warnf("Warning: NOASSERTION is unlikely for description field")
			}
		}
	}

	log.Debugf("Removed %d description entries from components\n", removedCount)
	if removedCount == 0 {
		log.Debugf("No description entries removed\n")
	}
	return nil
}

func RemoveHashFromComponent(doc *cydx.BOM, entries []interface{}, params *types.RmParams) error {
	log := logger.FromContext(*params.Ctx)
	removedCount := 0
	for _, e := range entries {
		entry, ok := e.(HashEntry)
		if !ok || entry.Hash == nil {
			log.Debugf("Skipping invalid hash entry: %v", e)
			continue
		}

		comp := entry.Component
		found := false
		if doc.Metadata.Component != nil && comp == doc.Metadata.Component {
			found = true
		} else if doc.Components != nil {
			for i := range *doc.Components {
				if &(*doc.Components)[i] == comp {
					found = true
					break
				}
			}
		}
		if !found {
			log.Warnf("Warning: Component %s@%s not found in document\n", comp.Name, comp.Version)
			continue
		}

		if params.Value == "NOASSERTION" {
			log.Warnf("Warning: NOASSERTION is unlikely for hash field")
		}

		if comp.Hashes != nil {
			var newHashes []cydx.Hash
			for _, hash := range *comp.Hashes {
				if !strings.EqualFold(hash.Value, entry.Hash.Value) {
					newHashes = append(newHashes, hash)
				} else {
					removedCount++
					log.Debugf("Removed hash from component: %s@%s, Hash: %s (%s)\n",
						comp.Name, comp.Version, hash.Value, hash.Algorithm)
				}
			}
			comp.Hashes = &newHashes
			if len(newHashes) == 0 {
				comp.Hashes = nil
			}
		}
	}

	log.Debugf("Removed %d hash entries from components\n", removedCount)
	if len(entries) > 0 && removedCount == 0 {
		log.Debugf("No hash entries removed\n")
	}
	return nil
}

func RemoveLicenseFromComponent(doc *cydx.BOM, entries []interface{}, params *types.RmParams) error {
	log := logger.FromContext(*params.Ctx)
	removedCount := 0
	for _, e := range entries {
		entry, ok := e.(LicenseEntry)
		if !ok || entry.Value == "" {
			log.Debugf("Skipping invalid license entry: %v", e)
			continue
		}

		comp := entry.Component
		found := false
		if doc.Metadata.Component != nil && comp == doc.Metadata.Component {
			found = true
		} else if doc.Components != nil {
			for i := range *doc.Components {
				if &(*doc.Components)[i] == comp {
					found = true
					break
				}
			}
		}
		if !found {
			log.Warnf("Warning: Component %s@%s not found in document\n", comp.Name, comp.Version)
			continue
		}

		if params.Value == "NOASSERTION" {
			log.Warnf("Warning: NOASSERTION is unlikely for license field")
		}

		if comp.Licenses != nil {
			var newLicenses cydx.Licenses
			for _, license := range *comp.Licenses {
				licenseValue := license.License.ID
				field := "ID"
				if licenseValue == "" {
					licenseValue = license.License.Name
					field = "Name"
				}
				if licenseValue == "" {
					licenseValue = license.Expression
					field = "Expression"
				}
				if licenseValue == "" || !strings.EqualFold(licenseValue, entry.Value) {
					newLicenses = append(newLicenses, license)
				} else {
					removedCount++
					log.Debugf("Removed license from component: %s@%s, License: %s (Field: %s)\n",
						comp.Name, comp.Version, licenseValue, field)
				}
			}
			comp.Licenses = &newLicenses
			if len(newLicenses) == 0 {
				comp.Licenses = nil
			}
		}
	}

	log.Debugf("Removed %d license entries from components\n", removedCount)
	if len(entries) > 0 && removedCount == 0 {
		log.Debugf("No license entries removed\n")
	}
	return nil
}

func RemovePurlFromComponent(doc *cydx.BOM, entries []interface{}, params *types.RmParams) error {
	log := logger.FromContext(*params.Ctx)
	removedCount := 0

	for _, e := range entries {
		entry, ok := e.(PurlEntry)
		if !ok {
			log.Debugf("Skipping invalid PURL entry: %v", e)
			continue
		}

		comp := entry.Component

		found := false
		if doc.Metadata.Component != nil && comp == doc.Metadata.Component {
			found = true
		} else if doc.Components != nil {
			for i := range *doc.Components {
				if &(*doc.Components)[i] == comp {
					found = true
					break
				}
			}
		}

		if !found {
			log.Warnf("Warning: Component %s@%s not found in document\n", comp.Name, comp.Version)
			continue
		}

		if comp.PackageURL != "" && strings.EqualFold(comp.PackageURL, entry.Value) {
			comp.PackageURL = ""
			removedCount++
			log.Debugf("Removed PURL from component: %s@%s, PURL: %s\n", comp.Name, comp.Version, entry.Value)
			if params.Value == "NOASSERTION" {
				log.Warnf("Warning: NOASSERTION is unlikely for PURL field")
			}
		}
	}

	log.Debugf("Removed %d PURL entries from components\n", removedCount)
	if removedCount == 0 {
		log.Debugf("No PURL entries removed\n")
	}
	return nil
}

func RemoveRepoFromComponent(doc *cydx.BOM, entries []interface{}, params *types.RmParams) error {
	log := logger.FromContext(*params.Ctx)
	removedCount := 0
	for _, e := range entries {
		entry, ok := e.(RepositoryEntry)
		if !ok || entry.Ref == nil || (entry.Ref.Type != cydx.ERTypeVCS && entry.Ref.Type != cydx.ERTypeDistribution) {
			log.Debugf("Skipping invalid repository entry: %v", e)
			continue
		}

		comp := entry.Component
		found := false
		if doc.Metadata.Component != nil && comp == doc.Metadata.Component {
			found = true
		} else if doc.Components != nil {
			for i := range *doc.Components {
				if &(*doc.Components)[i] == comp {
					found = true
					break
				}
			}
		}
		if !found {
			log.Warnf("Warning: Component %s@%s not found in document\n", comp.Name, comp.Version)
			continue
		}

		if params.Value == "NOASSERTION" {
			log.Warnf("Warning: NOASSERTION is unlikely for repository field")
		}

		if comp.ExternalReferences != nil {
			var newRefs []cydx.ExternalReference
			for _, ref := range *comp.ExternalReferences {
				if ref.Type != entry.Ref.Type || !strings.EqualFold(ref.URL, entry.Ref.URL) {
					newRefs = append(newRefs, ref)
				} else {
					removedCount++
					log.Debugf("Removed repository from component: %s@%s, Repository: %s (Type: %s)\n",
						comp.Name, comp.Version, ref.URL, ref.Type)
				}
			}
			comp.ExternalReferences = &newRefs
			if len(newRefs) == 0 {
				comp.ExternalReferences = nil
			}
		}
	}

	log.Debugf("Removed %d repository entries from components\n", removedCount)
	if len(entries) > 0 && removedCount == 0 {
		log.Debugf("No repository entries removed\n")
	}
	return nil
}

func RemoveTypeFromComponent(doc *cydx.BOM, entries []interface{}, params *types.RmParams) error {
	log := logger.FromContext(*params.Ctx)
	removedCount := 0
	for _, e := range entries {
		entry, ok := e.(TypeEntry)
		if !ok || entry.Value == "" {
			log.Debugf("Skipping invalid type entry: %v", e)
			continue
		}

		comp := entry.Component
		found := false
		if doc.Metadata.Component != nil && comp == doc.Metadata.Component {
			found = true
		} else if doc.Components != nil {
			for i := range *doc.Components {
				if &(*doc.Components)[i] == comp {
					found = true
					break
				}
			}
		}
		if !found {
			log.Warnf("Warning: Component %s@%s not found in document\n", comp.Name, comp.Version)
			continue
		}

		if params.Value == "NOASSERTION" {
			log.Warnf("Warning: NOASSERTION is unlikely for type field\n")
		}

		if strings.EqualFold(string(comp.Type), string(entry.Value)) {
			comp.Type = "" // Default type
			removedCount++
			log.Debugf("Removed type from component: %s@%s, Type: %s\n", comp.Name, comp.Version, entry.Value)
		}
	}

	log.Debugf("Removed %d type entries from components\n", removedCount)
	if len(entries) > 0 && removedCount == 0 {
		log.Debugf("No type entries removed\n")
	}
	return nil
}
