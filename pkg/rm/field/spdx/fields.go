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
	"github.com/spdx/tools-golang/spdx"
)

// AuthorEntry for PackageOriginator
type AuthorEntry struct {
	Package    *spdx.Package
	Originator *spdx.Originator
}

// SupplierEntry for PackageSupplier
type SupplierEntry struct {
	Package  *spdx.Package
	Supplier *spdx.Supplier
}

// RepositoryEntry for PackageDownloadLocation
type RepositoryEntry struct {
	Package *spdx.Package
	Value   string
}

// LicenseEntry for PackageLicenseConcluded
type LicenseEntry struct {
	Package *spdx.Package
	Value   string
}

// TypeEntry for PackagePrimaryPurpose
type TypeEntry struct {
	Package *spdx.Package
	Value   string
}

// DescriptionEntry for PackageDescription
type DescriptionEntry struct {
	Package *spdx.Package
	Value   string
}

// CopyrightEntry for PackageCopyrightText
type CopyrightEntry struct {
	Package *spdx.Package
	Value   string
}

// CpeEntry for PackageExternalReferences with RefType cpe22Type/cpe23Type
type CpeEntry struct {
	Package *spdx.Package
	Ref     *spdx.PackageExternalReference
}

// HashEntry for PackageChecksums
type HashEntry struct {
	Package  *spdx.Package
	Checksum *spdx.Checksum
}

// PurlEntry for PackageExternalReferences with RefType purl (already defined)
type PurlEntry struct {
	Package *spdx.Package
	Ref     *spdx.PackageExternalReference
}
