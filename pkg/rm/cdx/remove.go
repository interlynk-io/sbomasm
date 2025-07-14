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
	"strings"

	cydx "github.com/CycloneDX/cyclonedx-go"
)

func RemoveSupplierFromMetadata(bom *cydx.BOM, targets []interface{}) error {
	if bom.Metadata.Supplier == nil {
		return nil
	}
	for _, tar := range targets {
		supplier, ok := tar.(cydx.OrganizationalEntity)
		if ok && matchSupplier(*bom.Metadata.Supplier, supplier) {
			bom.Metadata.Supplier = nil
			break
		}
	}
	return nil
}

func matchSupplier(a, b cydx.OrganizationalEntity) bool {
	return a.Name == b.Name
}

func RemoveLicenseFromMetadata(bom *cydx.BOM, targets []interface{}) error {
	if bom.Metadata.Licenses == nil {
		return nil
	}
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
	bom.Metadata.Licenses = &filtered
	return nil
}

func matchLicense(tar interface{}, lic cydx.LicenseChoice) bool {
	candidate, ok := tar.(cydx.LicenseChoice)
	if !ok {
		return false
	}
	return candidate.Expression == lic.Expression
}

func RemoveAuthorFromMetadata(bom *cydx.BOM, targets []interface{}) error {
	if bom.Metadata == nil || bom.Metadata.Authors == nil {
		return nil
	}

	var filtered []cydx.OrganizationalContact
	for _, author := range *bom.Metadata.Authors {
		match := false
		for _, tar := range targets {
			if matchAuthor(tar, author) {
				match = true
				break
			}
		}
		if !match {
			filtered = append(filtered, author)
		}
	}
	bom.Metadata.Authors = &filtered
	return nil
}

func matchAuthor(tar interface{}, author cydx.OrganizationalContact) bool {
	candidate, ok := tar.(cydx.OrganizationalContact)
	if !ok {
		return false
	}
	return candidate.Name == author.Name && candidate.Email == author.Email
}

func RemoveLifecycleFromMetadata(bom *cydx.BOM, targets []interface{}) error {
	if bom.Metadata == nil || bom.Metadata.Lifecycles == nil {
		return nil
	}

	var filtered []cydx.Lifecycle
	for _, lifecycle := range *bom.Metadata.Lifecycles {
		match := false
		for _, target := range targets {
			if candidate, ok := target.(cydx.Lifecycle); ok && matchLifecycle(candidate, lifecycle) {
				match = true
				break
			}
		}
		if !match {
			filtered = append(filtered, lifecycle)
		}
	}

	bom.Metadata.Lifecycles = &filtered
	return nil
}

func matchLifecycle(a, b cydx.Lifecycle) bool {
	return a.Phase == b.Phase && a.Description == b.Description
}

func RemoveRepositoryFromMetadata(bom *cydx.BOM, targets []interface{}) error {
	if bom.Metadata == nil || bom.ExternalReferences == nil {
		return nil
	}

	var filtered []cydx.ExternalReference
	for _, ref := range *bom.ExternalReferences {
		if strings.ToLower(string(ref.Type)) != "vcs" {
			filtered = append(filtered, ref)
			continue
		}

		match := false
		for _, target := range targets {
			if candidate, ok := target.(cydx.ExternalReference); ok && matchExternalReference(candidate, ref) {
				match = true
				break
			}
		}

		if !match {
			filtered = append(filtered, ref)
		}
	}
	bom.ExternalReferences = &filtered
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

	// Handle v1.5+ tools (Components)
	if bom.SpecVersion > cydx.SpecVersion1_4 {
		if bom.Metadata.Tools.Components != nil {
			var filtered []cydx.Component
			for _, tool := range *bom.Metadata.Tools.Components {
				match := false
				for _, tar := range targets {
					if candidate, ok := tar.(cydx.Component); ok {
						if tool.Name == candidate.Name && tool.Version == candidate.Version {
							match = true
							break
						}
					}
				}
				if !match {
					filtered = append(filtered, tool)
				}
			}
			bom.Metadata.Tools.Components = &filtered
		}
	} else {
		// Handle <= v1.4 tools (Tool struct)
		if bom.Metadata.Tools.Tools != nil {
			var filtered []cydx.Tool
			for _, tool := range *bom.Metadata.Tools.Tools {
				match := false
				for _, tar := range targets {
					if candidate, ok := tar.(cydx.Tool); ok {
						if tool.Name == candidate.Name && tool.Version == candidate.Version {
							match = true
							break
						}
					}
				}
				if !match {
					filtered = append(filtered, tool)
				}
			}
			bom.Metadata.Tools.Tools = &filtered
		}
	}

	return nil
}
