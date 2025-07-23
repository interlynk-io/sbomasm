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

import cydx "github.com/CycloneDX/cyclonedx-go"

// AuthorEntry for Component.Author
type AuthorEntry struct {
	Component *cydx.Component
	Author    *cydx.OrganizationalContact
}

// SupplierEntry for Component.Supplier.Name
type SupplierEntry struct {
	Component *cydx.Component
	Value     string
}

// RepositoryEntry for ExternalReferences with Type "vcs"
type RepositoryEntry struct {
	Component *cydx.Component
	Ref       *cydx.ExternalReference
}

// LicenseEntry for Licenses (treating as string for simplicity)
type LicenseEntry struct {
	Component *cydx.Component
	Value     string // License ID, Name, or expression
}

// TypeEntry for Component.Type
type TypeEntry struct {
	Component *cydx.Component
	Value     cydx.ComponentType
}

// DescriptionEntry for Component.Description
type DescriptionEntry struct {
	Component *cydx.Component
	Value     string
}

// CopyrightEntry for Component.Copyright
type CopyrightEntry struct {
	Component *cydx.Component
	Value     string
}

// CpeEntry for ExternalReferences with Type "security" (for CPEs)
type CpeEntry struct {
	Component *cydx.Component
	Ref       string
}

// HashEntry for Hashes
type HashEntry struct {
	Component *cydx.Component
	Hash      *cydx.Hash
}

// PurlEntry for Component.PURL or ExternalReferences with Type "purl"
type PurlEntry struct {
	Component *cydx.Component
	Value     string // Use string for PURL to handle Component.PURL
}
