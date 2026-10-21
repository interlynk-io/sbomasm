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

package cdx

import (
	"os"
	"path/filepath"
	"testing"
)

// metadata.component is optional in CycloneDX, so a BOM can arrive without one.
var noPrimarySBOMa = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": 1,
  "components": [
    {
      "type": "library",
      "name": "liba",
      "version": "1.0.0",
      "bom-ref": "pkg:maven/liba@1.0.0"
    }
  ]
}`)

var noPrimarySBOMb = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": 1,
  "components": [
    {
      "type": "library",
      "name": "libb",
      "version": "1.0.0",
      "bom-ref": "pkg:maven/libb@1.0.0"
    }
  ]
}`)

// Hierarchical merge is the default. With no metadata.component anywhere the
// primary component list is empty, and the loop used to index it at 0.
func TestHierarchicalMergeWithoutPrimaryComponents(t *testing.T) {
	ctx := setupTestContext()

	dir := t.TempDir()
	pathA := filepath.Join(dir, "a.cdx.json")
	pathB := filepath.Join(dir, "b.cdx.json")
	if err := os.WriteFile(pathA, noPrimarySBOMa, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pathB, noPrimarySBOMb, 0o600); err != nil {
		t.Fatal(err)
	}

	ms := &MergeSettings{
		Ctx:   &ctx,
		Input: input{Files: []string{pathA, pathB}},
		Assemble: assemble{
			HierarchicalMerge: true,
		},
		App: app{Name: "testapp", Version: "1.0.0", PrimaryPurpose: "application"},
	}

	if err := newMerge(ms).combinedMerge(); err != nil {
		t.Fatalf("combinedMerge failed: %v", err)
	}
}
