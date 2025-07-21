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
		if creator.CreatorType != "Person" {
			// Keep non-author creators
			filtered = append(filtered, creator)
			continue
		}

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

func RemovePurlFromComponent(entries []interface{}, params *types.RmParams) error {
	for _, e := range entries {
		pkg, ok := e.(*spdx.Package)
		if !ok {
			continue
		}

		var newRefs []*spdx.PackageExternalReference
		for _, ref := range pkg.PackageExternalReferences {
			if ref.RefType != "purl" {
				newRefs = append(newRefs, ref)
			}
		}
		pkg.PackageExternalReferences = newRefs
	}
	return nil
}

func RemoveCopyrightFromComponent(entries []interface{}, params *types.RmParams) error {
	for _, e := range entries {
		pkg, ok := e.(*spdx.Package)
		if !ok {
			continue
		}
		pkg.PackageCopyrightText = ""
	}
	return nil
}

func RemoveCpeFromComponent(entries []interface{}, params *types.RmParams) error {
	for _, e := range entries {
		pkg, ok := e.(*spdx.Package)
		if !ok {
			continue
		}

		var newRefs []*spdx.PackageExternalReference
		for _, ref := range pkg.PackageExternalReferences {
			if ref.RefType != "cpe" {
				newRefs = append(newRefs, ref)
			}
		}
		pkg.PackageExternalReferences = newRefs
	}
	return nil
}

func RemoveDescriptionFromComponent(entries []interface{}, params *types.RmParams) error {
	for _, e := range entries {
		pkg, ok := e.(*spdx.Package)
		if !ok {
			continue
		}
		pkg.PackageDescription = ""
	}
	return nil
}

func RemoveHashFromComponent(entries []interface{}, params *types.RmParams) error {
	for _, e := range entries {
		pkg, ok := e.(*spdx.Package)
		if !ok {
			continue
		}

		var newChecksums []spdx.Checksum
		for _, checksum := range pkg.PackageChecksums {
			if checksum.Value != params.Value {
				newChecksums = append(newChecksums, checksum)
			}
		}
		pkg.PackageChecksums = newChecksums
	}
	return nil
}

func RemoveLicenseFromComponent(entries []interface{}, params *types.RmParams) error {
	for _, e := range entries {
		pkg, ok := e.(*spdx.Package)
		if !ok {
			continue
		}

		if pkg.PackageLicenseConcluded == params.Value {
			pkg.PackageLicenseConcluded = ""
			fmt.Println("🧹 Removed SPDX package license:", params.Value)
		}
	}
	return nil
}

func RemoveRepoFromComponent(entries []interface{}, params *types.RmParams) error {
	for _, e := range entries {
		pkg, ok := e.(*spdx.Package)
		if !ok {
			continue
		}

		if pkg.PackageDownloadLocation == params.Value {
			pkg.PackageDownloadLocation = ""
		}
	}
	return nil
}

func RemoveTypeFromComponent(entries []interface{}, params *types.RmParams) error {
	for _, e := range entries {
		pkg, ok := e.(*spdx.Package)
		if !ok {
			continue
		}

		if pkg.PrimaryPackagePurpose == params.Value {
			pkg.PrimaryPackagePurpose = ""
			fmt.Println("🧹 Removed SPDX package type:", params.Value)
		}

	}
	return nil
}

func RemoveSupplierFromComponent(entries []interface{}, params *types.RmParams) error {
	for _, e := range entries {
		pkg, ok := e.(*spdx.Package)
		if !ok {
			continue
		}
		pkg.PackageSupplier = nil
	}
	return nil
}
