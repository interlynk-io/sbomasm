// Copyright 2026 Interlynk.io
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

package edit

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/interlynk-io/sbomasm/v2/pkg/sbom"
	spdx3 "github.com/interlynk-io/spdx-zen/model/v3.0.1"
	"github.com/interlynk-io/spdx-zen/parse"
)

// spdx3Edit is the entry point for editing an SPDX 3.0 document.
// It loads the document, applies all configured mutations, and writes the
// result to the configured output path (or stdout if none is set).
func spdx3Edit(c *configParams) error {
	doc, err := loadSpdx3Document(*c.ctx, c.inputFilePath)
	if err != nil {
		return err
	}

	editDoc, err := NewSpdx3EditDoc(doc, c)
	if err != nil {
		return fmt.Errorf("failed to create spdx3 edit document: %w", err)
	}

	editDoc.update()

	return writeSpdx3Document(doc, c)
}

// loadSpdx3Document parses an SPDX 3.0 JSON-LD file at the given path into a
// *parse.Document using the shared sbom.Parser, which handles detection and
// routing automatically.
func loadSpdx3Document(ctx context.Context, path string) (*parse.Document, error) {
	sbomDoc, err := sbom.Parser(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to parse SPDX 3.0 file %q: %w", path, err)
	}

	spdx3Doc, ok := sbomDoc.(*sbom.SPDX3Document)
	if !ok {
		return nil, fmt.Errorf("expected *sbom.SPDX3Document, got %T", sbomDoc)
	}

	return spdx3Doc.Doc, nil
}

// writeSpdx3Document serializes the mutated document to the configured output.
// If no output path is set, it writes pretty-printed JSON-LD to stdout.
func writeSpdx3Document(doc *parse.Document, c *configParams) error {
	var output io.Writer

	if c.shouldOutput() {
		file, err := os.Create(c.outputFilePath)
		if err != nil {
			return fmt.Errorf("failed to create output file %q: %w", c.outputFilePath, err)
		}
		defer file.Close()
		output = file
	} else {
		output = os.Stdout
	}

	wrapper := &sbom.SPDX3Document{Doc: doc}
	if err := sbom.WriteSBOM(output, wrapper); err != nil {
		return fmt.Errorf("failed to write SPDX 3.0 document: %w", err)
	}

	return nil
}

// findPrimaryPackage returns the package referenced by the first rootElement
// of the SpdxDocument. SPDX 3.0 identifies the primary component through
// the SpdxDocument.rootElement list rather than a DESCRIBES relationship.
func findPrimaryPackage(doc *parse.Document) (*spdx3.Package, error) {
	if doc.SpdxDocument == nil {
		return nil, fmt.Errorf("document contains no SpdxDocument")
	}

	rootElements := doc.SpdxDocument.RootElement
	if len(rootElements) == 0 {
		return nil, fmt.Errorf("SpdxDocument has no rootElement")
	}

	primaryID := rootElements[0].SpdxID
	if primaryID == "" {
		return nil, fmt.Errorf("rootElement has empty spdxId")
	}

	pkg := findPackageInDocument(doc, primaryID)
	if pkg == nil {
		return nil, fmt.Errorf("primary package not found: %s", primaryID)
	}

	return pkg, nil
}

// findPackageByNameAndVersion searches all packages in the document for one
// whose Name and PackageVersion exactly match the given values.
func findPackageByNameAndVersion(doc *parse.Document, name, version string) (*spdx3.Package, error) {
	for _, pkg := range doc.Packages {
		if pkg.Name == name && pkg.PackageVersion == version {
			return pkg, nil
		}
	}
	return nil, fmt.Errorf("package not found: %s@%s", name, version)
}

// findPackageInDocument searches the document's Packages slice for a package
// with the given SpdxID. Returns nil if no match is found.
func findPackageInDocument(doc *parse.Document, spdxID string) *spdx3.Package {
	for _, pkg := range doc.Packages {
		if pkg.SpdxID == spdxID {
			return pkg
		}
	}
	return nil
}
