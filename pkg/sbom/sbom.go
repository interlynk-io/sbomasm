// Copyright 2025 Interlynk.io
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package sbom

import (
	cydx "github.com/CycloneDX/cyclonedx-go"
	"github.com/interlynk-io/spdx-zen/parse"
	"github.com/spdx/tools-golang/spdx/common"
)

// SBOMDocument is the common interface for all parsed SBOM documents.
// It provides uniform access to the underlying spec type and raw document.
type SBOMDocument interface {
	SpecType() string
	Document() any
}

// SPDXDocument wraps an SPDX 2.x/2.3 document parsed by spdx/tools-golang.
type SPDXDocument struct {
	Doc common.AnyDocument
}

// SpecType returns the SBOM spec identifier for this document.
func (s *SPDXDocument) SpecType() string { return "spdx" }

// Document returns the underlying spdx/tools-golang document.
func (s *SPDXDocument) Document() any { return s.Doc }

// SPDX3Document wraps spdx_zen's parsed SPDX 3.0 document.
// The *parse.Document is kept alive for mutation and serialization.
type SPDX3Document struct {
	Doc     *parse.Document
	Version FormatVersion
	Format  FileFormat
}

// SpecType returns the SBOM spec identifier for this document.
func (s *SPDX3Document) SpecType() string { return "spdx" }

// Document returns the underlying spdx_zen document.
func (s *SPDX3Document) Document() any { return s.Doc }

// CycloneDXDocument wraps a parsed CycloneDX BOM.
type CycloneDXDocument struct {
	BOM *cydx.BOM
}

// SpecType returns the SBOM spec identifier for this document.
func (c *CycloneDXDocument) SpecType() string { return "cdx" }

// Document returns the underlying CycloneDX BOM.
func (c *CycloneDXDocument) Document() any { return c.BOM }
