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

package rm

import (
	"bytes"
	"context"
	"testing"

	cydx "github.com/CycloneDX/cyclonedx-go"
	"github.com/interlynk-io/sbomasm/v2/pkg/rm/types"
	"github.com/interlynk-io/sbomasm/v2/pkg/sbom"
)

// parseCdxFromBytes parses a CycloneDX JSON BOM from bytes.
func parseCdxFromBytes(t *testing.T, data []byte) *cydx.BOM {
	t.Helper()
	bom := new(cydx.BOM)
	decoder := cydx.NewBOMDecoder(bytes.NewReader(data), cydx.BOMFileFormatJSON)
	if err := decoder.Decode(bom); err != nil {
		t.Fatalf("failed to parse CycloneDX: %v", err)
	}
	return bom
}

// cdxDoc wraps a parsed CDX BOM as an SBOMDocument.
type cdxDoc struct {
	bom *cydx.BOM
}

func (d *cdxDoc) Document() interface{}  { return d.bom }
func (d *cdxDoc) SpecType() string       { return string(sbom.SBOMSpecCDX) }
func (d *cdxDoc) SpecKey() string        { return "cdx" }
func (d *cdxDoc) Format() string         { return "json" }
func (d *cdxDoc) WriteSBOM(path string)  {}

// TestSelectComponents_CDX_MetadataComponentOnly verifies that when a
// CycloneDX BOM has a metadata.component but no components array,
// SelectComponents still finds metadata.component.
func TestSelectComponents_CDX_MetadataComponentOnly(t *testing.T) {
	bom := parseCdxFromBytes(t, []byte(`{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "version": 1,
  "metadata": {
    "component": {
      "type": "application",
      "name": "myapp",
      "version": "1.0.0",
      "purl": "pkg:generic/myapp@1.0.0"
    }
  }
}`))

	doc := &cdxDoc{bom: bom}
	engine := FieldOperationComponentEngine{doc: doc}
	ctx := context.Background()

	// --all should find metadata.component
	allParams := &types.RmParams{
		AllComponents: true,
	}
	result, err := engine.SelectComponents(ctx, allParams)
	if err != nil {
		t.Fatalf("SelectComponents error: %v", err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 component with --all, got %d", len(result))
	}
	comp, ok := result[0].(*cydx.Component)
	if !ok {
		t.Fatalf("expected *cydx.Component, got %T", result[0])
	}
	if comp.Name != "myapp" {
		t.Errorf("expected name 'myapp', got %q", comp.Name)
	}

	// --name/--version search should also find metadata.component
	searchParams := &types.RmParams{
		ComponentName:    "myapp",
		ComponentVersion: "1.0.0",
	}
	result, err = engine.SelectComponents(ctx, searchParams)
	if err != nil {
		t.Fatalf("SelectComponents error: %v", err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 component with name/version search, got %d", len(result))
	}
	comp, ok = result[0].(*cydx.Component)
	if !ok {
		t.Fatalf("expected *cydx.Component, got %T", result[0])
	}
	if comp.Name != "myapp" {
		t.Errorf("expected name 'myapp', got %q", comp.Name)
	}

	// --name/--version search with non-matching name should return nothing
	missParams := &types.RmParams{
		ComponentName:    "other",
		ComponentVersion: "1.0.0",
	}
	result, err = engine.SelectComponents(ctx, missParams)
	if err != nil {
		t.Fatalf("SelectComponents error: %v", err)
	}
	if len(result) != 0 {
		t.Fatalf("expected 0 components for non-matching name, got %d", len(result))
	}
}
