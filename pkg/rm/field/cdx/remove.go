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
	"strings"

	cydx "github.com/CycloneDX/cyclonedx-go"
)

func RemoveSupplierFromMetadata(bom *cydx.BOM, targets []interface{}) error {
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
		fmt.Println("🧹 Removed 1 supplier from metadata.")
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

func RemoveLicenseFromMetadata(bom *cydx.BOM, targets []interface{}) error {
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
	if removedCount > 0 {
		fmt.Printf("🧹 Removed %d license(s) from metadata.\n", removedCount)
	}

	if len(filtered) == 0 {
		bom.Metadata.Licenses = nil
	} else {
		bom.Metadata.Licenses = &filtered
	}

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

func RemoveAuthorFromMetadata(bom *cydx.BOM, targets []interface{}) error {
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
	fmt.Printf("🧹 Removed %d author(s) from metadata.\n", removedCount)

	if len(filtered) == 0 {
		bom.Metadata.Authors = nil
	} else {
		bom.Metadata.Authors = &filtered
	}

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

func RemoveLifecycleFromMetadata(bom *cydx.BOM, targets []interface{}) error {
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
	fmt.Printf("🧹 Removed %d lifecycle(s) from metadata.\n", removedCount)

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

func RemoveRepositoryFromMetadata(bom *cydx.BOM, targets []interface{}) error {
	if bom.Metadata == nil || bom.ExternalReferences == nil {
		return nil
	}

	var (
		filtered []cydx.ExternalReference
		removed  int
	)

	for _, ref := range *bom.ExternalReferences {
		// Only consider VCS-type references
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

	fmt.Printf("🧹 Removed %d repository (VCS) reference(s) from metadata.\n", removed)
	return nil
}

func matchExternalReference(a, b cydx.ExternalReference) bool {
	return a.Type == b.Type && a.URL == b.URL && a.Comment == b.Comment
}

func RemoveTimestampFromMetadata(bom *cydx.BOM, targets []interface{}) error {
	if bom.Metadata == nil {
		return nil
	}
	bom.Metadata.Timestamp = ""
	return nil
}

func RemoveToolFromMetadata(bom *cydx.BOM, targets []interface{}) error {
	if bom.Metadata == nil || bom.Metadata.Tools == nil {
		return nil
	}

	removedCount := 0

	matchToolByNameAndVersion := func(aName, aVersion, bName, bVersion string) bool {
		return aName == bName && aVersion == bVersion
	}

	if bom.SpecVersion > cydx.SpecVersion1_4 {
		// v1.5+ tools as components
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
	} else {
		// v1.4 and earlier: tools are of type Tool
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
	}

	// Cleanup: If both Tools and Components are empty or nil, remove the Tools block entirely
	if (bom.Metadata.Tools.Tools == nil || len(*bom.Metadata.Tools.Tools) == 0) &&
		(bom.Metadata.Tools.Components == nil || len(*bom.Metadata.Tools.Components) == 0) {
		bom.Metadata.Tools = nil
	}

	fmt.Printf("🧹 Removed %d tool(s) from metadata.\n", removedCount)
	return nil
}
