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
	"github.com/interlynk-io/spdx-zen/model/v3.0.1"
)

// PersonEntry wraps a resolved Person element from CreationInfo.CreatedBy
type PersonEntry struct {
	SpdxID string
	Person *spdx.Person
}

// OrgEntry wraps a resolved Organization element from CreationInfo.CreatedBy
type OrgEntry struct {
	SpdxID       string
	Organization *spdx.Organization
}

// ToolEntry wraps a resolved Tool element from CreationInfo.CreatedUsing
type ToolEntry struct {
	SpdxID string
	Tool   *spdx.Tool
}

// LicenseEntry wraps the SpdxDocument DataLicense
type LicenseEntry struct {
	License *spdx.AnyLicenseInfo
}

// ComponentAuthorEntry binds a Person reference back to its component
type ComponentAuthorEntry struct {
	Component *spdx.Package
	Person    *spdx.Person
	AgentIdx  int // index in Component.OriginatedBy
}

// ComponentSupplierEntry binds an Organization reference back to its component
type ComponentSupplierEntry struct {
	Component *spdx.Package
	Org       *spdx.Organization
}

// ComponentLicenseEntry binds a concluded license relationship back to its component
type ComponentLicenseEntry struct {
	Component    *spdx.Package
	Relationship *spdx.Relationship
	LicenseExpr  string // SpdxID (reference URL)
	LicenseName  string // resolved license name for value filtering
}

// ComponentTypeEntry binds a type value back to its component
type ComponentTypeEntry struct {
	Component *spdx.Package
	Value     string
}

// ComponentDescriptionEntry binds a description back to its component
type ComponentDescriptionEntry struct {
	Component *spdx.Package
	Value     string
}

// ComponentCopyrightEntry binds a copyright text back to its component
type ComponentCopyrightEntry struct {
	Component *spdx.Package
	Value     string
}

// ComponentExternalIdentifierEntry binds an external identifier back to its component
type ComponentExternalIdentifierEntry struct {
	Component *spdx.Package
	ExtId     *spdx.ExternalIdentifier
}

// ComponentExternalRefEntry binds an external ref back to its component
type ComponentExternalRefEntry struct {
	Component *spdx.Package
	ExtRef    *spdx.ExternalRef
}

// ComponentHashEntry binds a hash back to its component
type ComponentHashEntry struct {
	Component *spdx.Package
	Hash      *spdx.Hash
}

// SbomEntry binds an SbomType value back to its Sbom element
type SbomEntry struct {
	Sbom     *spdx.Sbom
	SbomType []spdx.SbomType
}

// RepoEntry binds an ExternalRef back to the SpdxDocument
type RepoEntry struct {
	Doc       *spdx.SpdxDocument
	ExtRef    *spdx.ExternalRef
	ExtRefIdx int // index in doc.ExternalRef
}
