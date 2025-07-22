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
	"strings"

	"github.com/interlynk-io/sbomasm/pkg/rm/types"
	"github.com/spdx/tools-golang/spdx"
)

func RemoveAuthorFromMetadata(doc *spdx.Document, targets []interface{}) error {
	if doc.CreationInfo == nil || len(doc.CreationInfo.Creators) == 0 {
		return nil
	}

	original := doc.CreationInfo.Creators
	var filtered []spdx.Creator

	for _, creator := range original {

		shouldRemove := false
		for _, target := range targets {
			tar, ok := target.(spdx.Creator)
			if ok && creator.Creator == tar.Creator {
				shouldRemove = true
				break
			}
		}

		if !shouldRemove {
			filtered = append(filtered, creator)
		}
	}

	removedCount := len(original) - len(filtered)
	doc.CreationInfo.Creators = filtered
	fmt.Printf("🧹 Removed %d SPDX author(s) from CreationInfo.\n", removedCount)
	return nil
}

func RemoveLicenseFromMetadata(doc *spdx.Document, targets []interface{}) error {
	removed := false
	for _, t := range targets {
		val, ok := t.(string)
		if !ok {
			continue
		}
		if doc.DataLicense == val {
			doc.DataLicense = ""
			removed = true
		}
	}
	if removed {
		fmt.Println("🧹 Removed SPDX document-level license (dataLicense).")
	}
	return nil
}

func RemoveLifecycleFromMetadata(doc *spdx.Document, targets []interface{}) error {
	if doc == nil || doc.CreationInfo == nil {
		return nil
	}

	for _, t := range targets {
		val, ok := t.(string)
		if !ok {
			continue
		}
		if doc.CreationInfo.CreatorComment == val {
			doc.CreationInfo.CreatorComment = ""
			fmt.Println("🧹 Removed SPDX lifecycle entry from CreatorComment.")
			return nil
		}
	}
	return nil
}

func RemoveSupplierFromMetadata(doc *spdx.Document, targets []interface{}) error {
	if doc == nil || doc.CreationInfo == nil {
		return nil
	}

	original := doc.CreationInfo.Creators
	var filtered []spdx.Creator
	for _, creator := range original {
		isMatch := false
		if creator.CreatorType == "Organization" {
			for _, tar := range targets {
				candidate, ok := tar.(spdx.Creator)
				if ok && candidate.Creator == creator.Creator {
					isMatch = true
					break
				}
			}
		}
		if !isMatch {
			filtered = append(filtered, creator)
		}
	}

	doc.CreationInfo.Creators = filtered

	removedCount := len(original) - len(filtered)
	if removedCount > 0 {
		fmt.Printf("🧹 Removed %d SPDX supplier(s) from CreatorInfo.\n", removedCount)
	}
	return nil
}

func RemoveToolFromMetadata(doc *spdx.Document, targets []interface{}) error {
	if doc == nil || doc.CreationInfo == nil {
		return nil
	}

	original := doc.CreationInfo.Creators
	var filtered []spdx.Creator
	for _, creator := range original {
		if creator.CreatorType == "Tool" {
			match := false
			for _, tar := range targets {
				candidate, ok := tar.(spdx.Creator)
				if ok && candidate.Creator == creator.Creator {
					match = true
					break
				}
			}
			if match {
				continue // skip adding matched tool
			}
		}
		filtered = append(filtered, creator)
	}

	doc.CreationInfo.Creators = filtered

	removed := len(original) - len(filtered)
	if removed > 0 {
		fmt.Printf("🧹 Removed %d SPDX tool(s) from CreationInfo.\n", removed)
	}
	return nil
}

func RemoveTimestampFromMetadata(doc *spdx.Document, targets []interface{}) error {
	if doc.CreationInfo == nil || doc.CreationInfo.Created == "" {
		return nil
	}

	for _, target := range targets {
		if ts, ok := target.(string); ok && ts == doc.CreationInfo.Created {
			doc.CreationInfo.Created = ""
			fmt.Println("🧹 Removed SPDX timestamp from CreationInfo.")
			break
		}
	}

	return nil
}

func RemovePurlFromComponent(doc *spdx.Document, targets []interface{}, params *types.RmParams) error {
	removedCount := 0

	for _, e := range targets {
		entry, ok := e.(PurlEntry)
		if !ok || entry.Ref.RefType != "purl" {
			fmt.Println("Skipping invalid PURL entry:", e)
			continue
		}

		pkg := entry.Package
		found := false

		for _, docPkg := range doc.Packages {
			if docPkg == pkg {
				found = true
				break
			}
		}
		if !found {
			fmt.Printf("Warning: Package %s@%s not found in document\n", pkg.PackageName, pkg.PackageVersion)
			continue
		}

		var newRefs []*spdx.PackageExternalReference
		for _, ref := range pkg.PackageExternalReferences {
			if ref != entry.Ref {
				newRefs = append(newRefs, ref)
			}
		}

		removedCount += len(pkg.PackageExternalReferences) - len(newRefs)
		pkg.PackageExternalReferences = newRefs
		if len(pkg.PackageExternalReferences) == 0 {
			pkg.PackageExternalReferences = nil
		}
		fmt.Printf("Removed PURL %s from component %s@%s\n", entry.Ref.Locator, pkg.PackageName, pkg.PackageVersion)
	}

	fmt.Printf("Removed %d PURL entries from components\n", removedCount)
	if removedCount == 0 {
		fmt.Println("No PURL entries removed")
	}

	// Optional: Validate document state
	if err := validatePackageReferences(doc); err != nil {
		fmt.Printf("Warning: Document validation failed: %v\n", err)
	}

	return nil
}

// validatePackageReferences checks if packages have required identifiers
func validatePackageReferences(doc *spdx.Document) error {
	for _, pkg := range doc.Packages {
		if pkg.PackageExternalReferences == nil && pkg.PackageSPDXIdentifier == "" {
			return fmt.Errorf("package %s@%s has no identifiers after removal", pkg.PackageName, pkg.PackageVersion)
		}
	}
	return nil
}

func RemoveAuthorFromComponent(doc *spdx.Document, entries []interface{}, params *types.RmParams) error {
	removedCount := 0
	for _, e := range entries {
		entry, ok := e.(AuthorEntry)
		if !ok || entry.Originator == nil {
			fmt.Println("Skipping invalid author entry:", e)
			continue
		}

		pkg := entry.Package
		// Verify package is in doc.Packages
		found := false
		for _, docPkg := range doc.Packages {
			if docPkg == pkg {
				found = true
				break
			}
		}
		if !found {
			fmt.Printf("Warning: Package %s@%s not found in document\n", pkg.PackageName, pkg.PackageVersion)
			continue
		}

		if pkg.PackageOriginator == entry.Originator {
			pkg.PackageOriginator = nil
			removedCount++
			fmt.Printf("Removed author from component: %s@%s, Author: %s\n", pkg.PackageName, pkg.PackageVersion, entry.Originator.Originator)
		}
	}

	fmt.Printf("Removed %d author entries from components\n", removedCount)
	if removedCount == 0 {
		fmt.Println("No author entries removed")
	}
	return nil
}

func RemoveSupplierFromComponent(doc *spdx.Document, entries []interface{}, params *types.RmParams) error {
	removedCount := 0
	for _, e := range entries {
		entry, ok := e.(SupplierEntry)
		if !ok || entry.Supplier == nil {
			fmt.Println("Skipping invalid supplier entry:", e)
			continue
		}

		pkg := entry.Package
		// Verify package is in doc.Packages
		found := false
		for _, docPkg := range doc.Packages {
			if docPkg == pkg {
				found = true
				break
			}
		}
		if !found {
			fmt.Printf("Warning: Package %s@%s not found in document\n", pkg.PackageName, pkg.PackageVersion)
			continue
		}

		if pkg.PackageSupplier == entry.Supplier {
			pkg.PackageSupplier = nil
			removedCount++
			fmt.Printf("Removed supplier from component: %s@%s, Supplier: %s\n", pkg.PackageName, pkg.PackageVersion, entry.Supplier.Supplier)
			if params.Value == "NOASSERTION" {
				fmt.Println("Matched NOASSERTION for supplier")
			}
		}
	}

	fmt.Printf("Removed %d supplier entries from components\n", removedCount)
	if removedCount == 0 {
		fmt.Println("No supplier entries removed")
	}
	return nil
}

func RemoveCopyrightFromComponent(doc *spdx.Document, entries []interface{}, params *types.RmParams) error {
	removedCount := 0
	for _, e := range entries {
		entry, ok := e.(CopyrightEntry)
		if !ok || entry.Value == "" {
			fmt.Println("Skipping invalid copyright entry:", e)
			continue
		}

		pkg := entry.Package
		// Verify package is in doc.Packages
		found := false
		for _, docPkg := range doc.Packages {
			if docPkg == pkg {
				found = true
				break
			}
		}
		if !found {
			fmt.Printf("Warning: Package %s@%s not found in document\n", pkg.PackageName, pkg.PackageVersion)
			continue
		}

		if strings.EqualFold(pkg.PackageCopyrightText, entry.Value) {
			pkg.PackageCopyrightText = ""
			removedCount++
			fmt.Printf("Removed copyright from component: %s@%s, Copyright: %s\n", pkg.PackageName, pkg.PackageVersion, entry.Value)
			if params.Value == "NOASSERTION" {
				fmt.Println("Matched NOASSERTION for copyright")
			}
		}
	}

	fmt.Printf("Removed %d copyright entries from components\n", removedCount)
	if removedCount == 0 {
		fmt.Println("No copyright entries removed")
	}
	return nil
}

func RemoveCpeFromComponent(doc *spdx.Document, entries []interface{}, params *types.RmParams) error {
	removedCount := 0
	for _, e := range entries {
		entry, ok := e.(CpeEntry)
		if !ok || entry.Ref == nil || (entry.Ref.RefType != "cpe22Type" && entry.Ref.RefType != "cpe23Type") {
			fmt.Println("Skipping invalid CPE entry:", e)
			continue
		}

		pkg := entry.Package
		// Verify package is in doc.Packages
		found := false
		for _, docPkg := range doc.Packages {
			if docPkg == pkg {
				found = true
				break
			}
		}
		if !found {
			fmt.Printf("Warning: Package %s@%s not found in document\n", pkg.PackageName, pkg.PackageVersion)
			continue
		}

		var newRefs []*spdx.PackageExternalReference
		for _, ref := range pkg.PackageExternalReferences {
			if ref != entry.Ref {
				newRefs = append(newRefs, ref)
			}
		}
		removedCount += len(pkg.PackageExternalReferences) - len(newRefs)
		pkg.PackageExternalReferences = newRefs
		if len(newRefs) == 0 {
			pkg.PackageExternalReferences = nil
		}
		fmt.Printf("Removed CPE from component: %s@%s, CPE: %s\n", pkg.PackageName, pkg.PackageVersion, entry.Ref.Locator)
		if params.Value == "NOASSERTION" {
			fmt.Println("Warning: NOASSERTION is unlikely for CPE field")
		}
	}

	fmt.Printf("Removed %d CPE entries from components\n", removedCount)
	if removedCount == 0 {
		fmt.Println("No CPE entries removed")
	}
	return nil
}

func RemoveDescriptionFromComponent(doc *spdx.Document, entries []interface{}, params *types.RmParams) error {
	removedCount := 0
	for _, e := range entries {
		entry, ok := e.(DescriptionEntry)
		if !ok || entry.Value == "" {
			fmt.Println("Skipping invalid description entry:", e)
			continue
		}

		pkg := entry.Package
		// Verify package is in doc.Packages
		found := false
		for _, docPkg := range doc.Packages {
			if docPkg == pkg {
				found = true
				break
			}
		}
		if !found {
			fmt.Printf("Warning: Package %s@%s not found in document\n", pkg.PackageName, pkg.PackageVersion)
			continue
		}

		if strings.EqualFold(pkg.PackageDescription, entry.Value) {
			pkg.PackageDescription = ""
			removedCount++
			fmt.Printf("Removed description from component: %s@%s, Description: %s\n", pkg.PackageName, pkg.PackageVersion, entry.Value)
			if params.Value == "NOASSERTION" {
				fmt.Println("Warning: NOASSERTION is unlikely for description field")
			}
		}
	}

	fmt.Printf("Removed %d description entries from components\n", removedCount)
	if removedCount == 0 {
		fmt.Println("No description entries removed")
	}
	return nil
}

func RemoveHashFromComponent(doc *spdx.Document, entries []interface{}, params *types.RmParams) error {
	removedCount := 0
	for _, e := range entries {
		entry, ok := e.(HashEntry)
		if !ok || entry.Checksum == nil {
			fmt.Println("Skipping invalid hash entry:", e)
			continue
		}

		pkg := entry.Package
		// Verify package is in doc.Packages
		found := false
		for _, docPkg := range doc.Packages {
			if docPkg == pkg {
				found = true
				break
			}
		}
		if !found {
			fmt.Printf("Warning: Package %s@%s not found in document\n", pkg.PackageName, pkg.PackageVersion)
			continue
		}

		var newChecksums []spdx.Checksum
		for _, checksum := range pkg.PackageChecksums {
			if checksum != *entry.Checksum {
				newChecksums = append(newChecksums, checksum)
			}
		}
		removedCount += len(pkg.PackageChecksums) - len(newChecksums)
		pkg.PackageChecksums = newChecksums
		if len(newChecksums) == 0 {
			pkg.PackageChecksums = nil
		}
		fmt.Printf("Removed hash from component: %s@%s, Hash: %s\n", pkg.PackageName, pkg.PackageVersion, entry.Checksum.Value)
		if params.Value == "NOASSERTION" {
			fmt.Println("Warning: NOASSERTION is unlikely for hash field")
		}
	}

	fmt.Printf("Removed %d hash entries from components\n", removedCount)
	if removedCount == 0 {
		fmt.Println("No hash entries removed")
	}
	return nil
}

func RemoveLicenseFromComponent(doc *spdx.Document, entries []interface{}, params *types.RmParams) error {
	removedCount := 0
	for _, e := range entries {
		entry, ok := e.(LicenseEntry)
		if !ok || entry.Value == "" {
			fmt.Println("Skipping invalid license entry:", e)
			continue
		}

		pkg := entry.Package
		// Verify package is in doc.Packages
		found := false
		for _, docPkg := range doc.Packages {
			if docPkg == pkg {
				found = true
				break
			}
		}
		if !found {
			fmt.Printf("Warning: Package %s@%s not found in document\n", pkg.PackageName, pkg.PackageVersion)
			continue
		}

		if strings.EqualFold(pkg.PackageLicenseConcluded, entry.Value) {
			pkg.PackageLicenseConcluded = ""
			removedCount++
			fmt.Printf("Removed license from component: %s@%s, License: %s\n", pkg.PackageName, pkg.PackageVersion, entry.Value)
			if params.Value == "NOASSERTION" {
				fmt.Println("Matched NOASSERTION for license")
			}
		}
	}

	fmt.Printf("Removed %d license entries from components\n", removedCount)
	if removedCount == 0 {
		fmt.Println("No license entries removed")
	}
	return nil
}

func RemoveRepoFromComponent(doc *spdx.Document, entries []interface{}, params *types.RmParams) error {
	removedCount := 0
	for _, e := range entries {
		entry, ok := e.(RepositoryEntry)
		if !ok || entry.Value == "" {
			fmt.Println("Skipping invalid repository entry:", e)
			continue
		}

		pkg := entry.Package
		// Verify package is in doc.Packages
		found := false
		for _, docPkg := range doc.Packages {
			if docPkg == pkg {
				found = true
				break
			}
		}
		if !found {
			fmt.Printf("Warning: Package %s@%s not found in document\n", pkg.PackageName, pkg.PackageVersion)
			continue
		}

		if strings.EqualFold(pkg.PackageDownloadLocation, entry.Value) {
			pkg.PackageDownloadLocation = ""
			removedCount++
			fmt.Printf("Removed repository from component: %s@%s, Repository: %s\n", pkg.PackageName, pkg.PackageVersion, entry.Value)
			if params.Value == "NOASSERTION" {
				fmt.Println("Warning: NOASSERTION is unlikely for repository field")
			}
		}
	}

	fmt.Printf("Removed %d repository entries from components\n", removedCount)
	if removedCount == 0 {
		fmt.Println("No repository entries removed")
	}
	return nil
}

func RemoveTypeFromComponent(doc *spdx.Document, entries []interface{}, params *types.RmParams) error {
	removedCount := 0
	for _, e := range entries {
		entry, ok := e.(TypeEntry)
		if !ok || entry.Value == "" {
			fmt.Println("Skipping invalid type entry:", e)
			continue
		}

		pkg := entry.Package
		// Verify package is in doc.Packages
		found := false
		for _, docPkg := range doc.Packages {
			if docPkg == pkg {
				found = true
				break
			}
		}
		if !found {
			fmt.Printf("Warning: Package %s@%s not found in document\n", pkg.PackageName, pkg.PackageVersion)
			continue
		}

		if strings.EqualFold(pkg.PrimaryPackagePurpose, entry.Value) {
			pkg.PrimaryPackagePurpose = ""
			removedCount++
			fmt.Printf("Removed type from component: %s@%s, Type: %s\n", pkg.PackageName, pkg.PackageVersion, entry.Value)
			if params.Value == "NOASSERTION" {
				fmt.Println("Warning: NOASSERTION is unlikely for type field")
			}
		}
	}

	fmt.Printf("Removed %d type entries from components\n", removedCount)
	if removedCount == 0 {
		fmt.Println("No type entries removed")
	}
	return nil
}
