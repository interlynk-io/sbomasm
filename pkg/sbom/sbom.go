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

type SBOMDocument interface {
	SpecType() string
	Document() any
}

type SPDXDocument struct {
	Doc common.AnyDocument
}

func (s *SPDXDocument) SpecType() string { return "spdx" }
func (s *SPDXDocument) Document() any    { return s.Doc }

// SPDX3Document wraps spdx_zen's parsed SPDX 3.0 document.
// The *parse.Document is kept alive for mutation and serialization.
type SPDX3Document struct {
	Doc     *parse.Document
	Version FormatVersion
	Format  FileFormat
}

func (s *SPDX3Document) SpecType() string { return "spdx" }
func (s *SPDX3Document) Document() any    { return s.Doc }

type CycloneDXDocument struct {
	BOM *cydx.BOM
}

func (c *CycloneDXDocument) SpecType() string { return "cdx" }
func (c *CycloneDXDocument) Document() any    { return c.BOM }
