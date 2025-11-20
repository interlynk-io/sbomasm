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
	"context"
	"fmt"
	"strings"

	"github.com/interlynk-io/sbomasm/v2/pkg/logger"
	"github.com/interlynk-io/sbomasm/v2/pkg/rm/types"
	"github.com/spdx/tools-golang/spdx"
)

func RemoveAuthorFromMetadata(ctx context.Context, doc *spdx.Document, targets []interface{}) error {
	log := logger.FromContext(ctx)
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
	log.Debugf("Removed %d SPDX author(s) from CreationInfo.\n", removedCount)
	return nil
}

func RemoveLicenseFromMetadata(ctx context.Context, doc *spdx.Document, targets []interface{}) error {
	log := logger.FromContext(ctx)
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
		log.Debugf("Removed SPDX document-level license (dataLicense).")
	}
	return nil
}

func RemoveLifecycleFromMetadata(ctx context.Context, doc *spdx.Document, targets []interface{}) error {
	log := logger.FromContext(ctx)
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
			log.Debugf("Removed SPDX lifecycle entry from CreatorComment.")
			return nil
		}
	}
	return nil
}

func RemoveSupplierFromMetadata(ctx context.Context, doc *spdx.Document, targets []interface{}) error {
	log := logger.FromContext(ctx)
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
		log.Debugf("Removed %d SPDX supplier(s) from CreatorInfo.\n", removedCount)
	}
	return nil
}

func RemoveToolFromMetadata(ctx context.Context, doc *spdx.Document, targets []interface{}) error {
	log := logger.FromContext(ctx)
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
		log.Debugf("Removed %d SPDX tool(s) from CreationInfo.\n", removed)
	}
	return nil
}

func RemoveTimestampFromMetadata(ctx context.Context, doc *spdx.Document, targets []interface{}) error {
	log := logger.FromContext(ctx)
	if doc.CreationInfo == nil || doc.CreationInfo.Created == "" {
		return nil
	}

	for _, target := range targets {
		if ts, ok := target.(string); ok && ts == doc.CreationInfo.Created {
			doc.CreationInfo.Created = ""
			break
		}
	}

	log.Debugf("Removed SPDX document creation timestamp.")
	return nil
}

func RemovePurlFromComponent(doc *spdx.Document, targets []interface{}, params *types.RmParams) error {
	log := logger.FromContext(*params.Ctx)
	removedCount := 0

	for _, e := range targets {
		entry, ok := e.(PurlEntry)
		if !ok || entry.Ref.RefType != "purl" {
			log.Debugf("Skipping invalid PURL entry: %v", e)
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
			log.Debugf("Warning: Package %s@%s not found in document\n", pkg.PackageName, pkg.PackageVersion)
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
	}

	log.Debugf("Removed %d PURL entries from components\n", removedCount)
	if removedCount == 0 {
		log.Debugf("No PURL entries removed\n")
	}

	return nil
}

func RemoveAuthorFromComponent(doc *spdx.Document, entries []interface{}, params *types.RmParams) error {
	log := logger.FromContext(*params.Ctx)
	removedCount := 0
	for _, e := range entries {
		entry, ok := e.(AuthorEntry)
		if !ok || entry.Originator == nil {
			log.Debugf("Skipping invalid author entry: %v", e)
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
			log.Debugf("Warning: Package %s@%s not found in document\n", pkg.PackageName, pkg.PackageVersion)
			continue
		}

		if pkg.PackageOriginator == entry.Originator {
			pkg.PackageOriginator = nil
			removedCount++
		}
	}

	log.Debugf("Removed %d author entries from components\n", removedCount)
	if removedCount == 0 {
		log.Debugf("No author entries removed\n")
	}
	return nil
}

func RemoveSupplierFromComponent(doc *spdx.Document, entries []interface{}, params *types.RmParams) error {
	log := logger.FromContext(*params.Ctx)
	removedCount := 0
	for _, e := range entries {
		entry, ok := e.(SupplierEntry)
		if !ok || entry.Supplier == nil {
			log.Debugf("Skipping invalid supplier entry: %v", e)
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
			log.Debugf("Warning: Package %s@%s not found in document\n", pkg.PackageName, pkg.PackageVersion)
			continue
		}

		if pkg.PackageSupplier == entry.Supplier {
			pkg.PackageSupplier = nil
			removedCount++
			if params.Value == "NOASSERTION" {
				log.Debugf("Matched NOASSERTION for supplier\n")
			}
		}
	}

	log.Debugf("Removed %d supplier entries from components\n", removedCount)
	if removedCount == 0 {
		log.Debugf("No supplier entries removed\n")
	}
	return nil
}

func RemoveCopyrightFromComponent(doc *spdx.Document, entries []interface{}, params *types.RmParams) error {
	log := logger.FromContext(*params.Ctx)
	removedCount := 0
	for _, e := range entries {
		entry, ok := e.(CopyrightEntry)
		if !ok || entry.Value == "" {
			log.Debugf("Skipping invalid copyright entry: %v", e)
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
			log.Debugf("Warning: Package %s@%s not found in document\n", pkg.PackageName, pkg.PackageVersion)
			continue
		}

		if strings.EqualFold(pkg.PackageCopyrightText, entry.Value) {
			pkg.PackageCopyrightText = ""
			removedCount++
			if params.Value == "NOASSERTION" {
				log.Debugf("Matched NOASSERTION for copyright\n")
			}
		}
	}

	log.Debugf("Removed %d copyright entries from components\n", removedCount)
	if removedCount == 0 {
		log.Debugf("No copyright entries removed\n")
	}
	return nil
}

func RemoveCpeFromComponent(doc *spdx.Document, entries []interface{}, params *types.RmParams) error {
	log := logger.FromContext(*params.Ctx)
	removedCount := 0
	for _, e := range entries {
		entry, ok := e.(CpeEntry)
		if !ok || entry.Ref == nil || (entry.Ref.RefType != "cpe22Type" && entry.Ref.RefType != "cpe23Type") {
			log.Debugf("Skipping invalid CPE entry: %v", e)
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
			log.Debugf("Warning: Package %s@%s not found in document\n", pkg.PackageName, pkg.PackageVersion)
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
		if params.Value == "NOASSERTION" {
			log.Debugf("Warning: NOASSERTION is unlikely for CPE field\n")
		}
	}

	log.Debugf("Removed %d CPE entries from components\n", removedCount)
	if removedCount == 0 {
		log.Debugf("No CPE entries removed\n")
	}
	return nil
}

func RemoveDescriptionFromComponent(doc *spdx.Document, entries []interface{}, params *types.RmParams) error {
	log := logger.FromContext(*params.Ctx)
	removedCount := 0
	for _, e := range entries {
		entry, ok := e.(DescriptionEntry)
		if !ok || entry.Value == "" {
			log.Debugf("Skipping invalid description entry: %v", e)
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
			log.Debugf("Warning: Package %s@%s not found in document\n", pkg.PackageName, pkg.PackageVersion)
			continue
		}

		if strings.EqualFold(pkg.PackageDescription, entry.Value) {
			pkg.PackageDescription = ""
			removedCount++
			if params.Value == "NOASSERTION" {
				log.Debugf("Warning: NOASSERTION is unlikely for description field\n")
			}
		}
	}

	log.Debugf("Removed %d description entries from components\n", removedCount)
	if removedCount == 0 {
		log.Debugf("No description entries removed\n")
	}
	return nil
}

func RemoveHashFromComponent(doc *spdx.Document, entries []interface{}, params *types.RmParams) error {
	log := logger.FromContext(*params.Ctx)
	removedCount := 0
	for _, e := range entries {
		entry, ok := e.(HashEntry)
		if !ok || entry.Checksum == nil {
			log.Debugf("Skipping invalid hash entry: %v", e)
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
			log.Debugf("Warning: Package %s@%s not found in document\n", pkg.PackageName, pkg.PackageVersion)
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
		if params.Value == "NOASSERTION" {
			log.Debugf("Warning: NOASSERTION is unlikely for hash field\n")
		}
	}

	log.Debugf("Removed %d hash entries from components\n", removedCount)
	if removedCount == 0 {
		log.Debugf("No hash entries removed\n")
	}
	return nil
}

func RemoveLicenseFromComponent(doc *spdx.Document, entries []interface{}, params *types.RmParams) error {
	log := logger.FromContext(*params.Ctx)
	removedCount := 0
	for _, e := range entries {
		entry, ok := e.(LicenseEntry)
		if !ok || entry.Value == "" {
			log.Debugf("Skipping invalid license entry: %v", e)
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

		if strings.EqualFold(pkg.PackageLicenseConcluded, entry.Value) {
			pkg.PackageLicenseConcluded = ""
			removedCount++
			if params.Value == "NOASSERTION" {
				log.Debugf("Matched NOASSERTION for license\n")
			}
		}
	}

	log.Debugf("Removed %d license entries from components\n", removedCount)
	if removedCount == 0 {
		log.Debugf("No license entries removed\n")
	}
	return nil
}

func RemoveRepoFromComponent(doc *spdx.Document, entries []interface{}, params *types.RmParams) error {
	log := logger.FromContext(*params.Ctx)
	removedCount := 0
	for _, e := range entries {
		entry, ok := e.(RepositoryEntry)
		if !ok || entry.Value == "" {
			log.Debugf("Skipping invalid repository entry: %v", e)
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
			log.Debugf("Warning: Package %s@%s not found in document\n", pkg.PackageName, pkg.PackageVersion)
			continue
		}

		if strings.EqualFold(pkg.PackageDownloadLocation, entry.Value) {
			pkg.PackageDownloadLocation = ""
			removedCount++
			if params.Value == "NOASSERTION" {
				log.Debugf("Warning: NOASSERTION is unlikely for repository field\n")
			}
		}
	}

	log.Debugf("Removed %d repository entries from components\n", removedCount)
	if removedCount == 0 {
		log.Debugf("No repository entries removed\n")
	}
	return nil
}

func RemoveTypeFromComponent(doc *spdx.Document, entries []interface{}, params *types.RmParams) error {
	log := logger.FromContext(*params.Ctx)
	removedCount := 0
	for _, e := range entries {
		entry, ok := e.(TypeEntry)
		if !ok || entry.Value == "" {
			log.Debugf("Skipping invalid type entry: %v", e)
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
			log.Debugf("Warning: Package %s@%s not found in document\n", pkg.PackageName, pkg.PackageVersion)
			continue
		}

		if strings.EqualFold(pkg.PrimaryPackagePurpose, entry.Value) {
			pkg.PrimaryPackagePurpose = ""
			removedCount++
			if params.Value == "NOASSERTION" {
				log.Debugf("Warning: NOASSERTION is unlikely for type field\n")
			}
		}
	}

	log.Debugf("Removed %d type entries from components\n", removedCount)
	if removedCount == 0 {
		log.Debugf("No type entries removed\n")
	}
	return nil
}
