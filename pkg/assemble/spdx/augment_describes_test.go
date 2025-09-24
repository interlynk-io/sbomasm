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
	"context"
	"testing"

	"github.com/spdx/tools-golang/spdx"
	"github.com/spdx/tools-golang/spdx/v2/common"
)

func TestAugmentMerge_DESCRIBES_Handling(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name                    string
		primary                 *spdx.Document
		secondary               *spdx.Document
		expectedDescribesCount  int
		expectedDescribedPkgID  string
		shouldHaveDescribes     bool
	}{
		{
			name: "Primary without DESCRIBES, single package - should add DESCRIBES when augmented",
			primary: &spdx.Document{
				SPDXVersion:       "SPDX-2.3",
				DataLicense:       "CC0-1.0",
				SPDXIdentifier:    "DOCUMENT",
				DocumentName:      "primary",
				DocumentNamespace: "https://example.com/primary",
				CreationInfo:      &spdx.CreationInfo{Created: "2025-01-01T00:00:00Z"},
				Packages: []*spdx.Package{
					{
						PackageName:           "MainPkg",
						PackageSPDXIdentifier: "SPDXRef-MainPkg",
						PackageVersion:        "1.0.0",
					},
				},
				Relationships: []*spdx.Relationship{},
			},
			secondary: &spdx.Document{
				SPDXVersion:       "SPDX-2.3",
				DataLicense:       "CC0-1.0",
				SPDXIdentifier:    "DOCUMENT",
				DocumentName:      "secondary",
				DocumentNamespace: "https://example.com/secondary",
				CreationInfo:      &spdx.CreationInfo{Created: "2025-01-01T00:00:00Z"},
				Packages: []*spdx.Package{
					{
						PackageName:           "SecPkg1",
						PackageSPDXIdentifier: "SPDXRef-SecPkg1",
						PackageVersion:        "2.0.0",
					},
				},
				Relationships: []*spdx.Relationship{
					{
						RefA:         common.MakeDocElementID("", "DOCUMENT"),
						RefB:         common.MakeDocElementID("", "SPDXRef-SecPkg1"),
						Relationship: common.TypeRelationshipDescribe,
					},
				},
			},
			expectedDescribesCount: 1,
			expectedDescribedPkgID: "SPDXRef-MainPkg",
			shouldHaveDescribes:    true,
		},
		{
			name: "Primary with DESCRIBES - should preserve and not copy secondary DESCRIBES",
			primary: &spdx.Document{
				SPDXVersion:       "SPDX-2.3",
				DataLicense:       "CC0-1.0",
				SPDXIdentifier:    "DOCUMENT",
				DocumentName:      "primary",
				DocumentNamespace: "https://example.com/primary",
				CreationInfo:      &spdx.CreationInfo{Created: "2025-01-01T00:00:00Z"},
				Packages: []*spdx.Package{
					{
						PackageName:           "PrimaryPkg",
						PackageSPDXIdentifier: "SPDXRef-PrimaryPkg",
						PackageVersion:        "1.0.0",
					},
				},
				Relationships: []*spdx.Relationship{
					{
						RefA:         common.MakeDocElementID("", "DOCUMENT"),
						RefB:         common.MakeDocElementID("", "SPDXRef-PrimaryPkg"),
						Relationship: common.TypeRelationshipDescribe,
					},
				},
			},
			secondary: &spdx.Document{
				SPDXVersion:       "SPDX-2.3",
				DataLicense:       "CC0-1.0",
				SPDXIdentifier:    "DOCUMENT",
				DocumentName:      "secondary",
				DocumentNamespace: "https://example.com/secondary",
				CreationInfo:      &spdx.CreationInfo{Created: "2025-01-01T00:00:00Z"},
				Packages: []*spdx.Package{
					{
						PackageName:           "SecPkg",
						PackageSPDXIdentifier: "SPDXRef-SecPkg",
						PackageVersion:        "2.0.0",
					},
					{
						PackageName:           "SecPkg2",
						PackageSPDXIdentifier: "SPDXRef-SecPkg2",
						PackageVersion:        "3.0.0",
					},
				},
				Relationships: []*spdx.Relationship{
					{
						RefA:         common.MakeDocElementID("", "DOCUMENT"),
						RefB:         common.MakeDocElementID("", "SPDXRef-SecPkg"),
						Relationship: common.TypeRelationshipDescribe,
					},
				},
			},
			expectedDescribesCount: 1,
			expectedDescribedPkgID: "SPDXRef-PrimaryPkg",
			shouldHaveDescribes:    true,
		},
		{
			name: "Multiple packages in primary without DESCRIBES - should add DESCRIBES to first",
			primary: &spdx.Document{
				SPDXVersion:       "SPDX-2.3",
				DataLicense:       "CC0-1.0",
				SPDXIdentifier:    "DOCUMENT",
				DocumentName:      "primary",
				DocumentNamespace: "https://example.com/primary",
				CreationInfo:      &spdx.CreationInfo{Created: "2025-01-01T00:00:00Z"},
				Packages: []*spdx.Package{
					{
						PackageName:           "Pkg1",
						PackageSPDXIdentifier: "SPDXRef-Pkg1",
						PackageVersion:        "1.0.0",
					},
					{
						PackageName:           "Pkg2",
						PackageSPDXIdentifier: "SPDXRef-Pkg2",
						PackageVersion:        "1.0.0",
					},
				},
				Relationships: []*spdx.Relationship{},
			},
			secondary: &spdx.Document{
				SPDXVersion:       "SPDX-2.3",
				DataLicense:       "CC0-1.0",
				SPDXIdentifier:    "DOCUMENT",
				DocumentName:      "secondary",
				DocumentNamespace: "https://example.com/secondary",
				CreationInfo:      &spdx.CreationInfo{Created: "2025-01-01T00:00:00Z"},
				Packages: []*spdx.Package{
					{
						PackageName:           "SecPkg",
						PackageSPDXIdentifier: "SPDXRef-SecPkg",
						PackageVersion:        "2.0.0",
					},
				},
				Relationships: []*spdx.Relationship{},
			},
			expectedDescribesCount: 1,
			expectedDescribedPkgID: "SPDXRef-Pkg1",
			shouldHaveDescribes:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create merge settings
			ms := &MergeSettings{
				Ctx: &ctx,
				Input: input{
					Files: []string{}, // Not used in this test
				},
				Output: output{
					FileFormat: "json",
				},
				Assemble: assemble{
					AugmentMerge: true,
					MergeMode:    "if-missing-or-empty",
				},
			}

			// Create augment merge instance
			am := newAugmentMerge(ms)
			am.primary = tt.primary
			am.secondary = []*spdx.Document{tt.secondary}

			// Setup matcher (simplified for test)
			_ = am.setupMatcher()
			_ = am.buildPrimaryIndex()

			// Process secondary SBOM
			am.processedPkgs = make(map[string]string)
			am.addedPkgIDs = make(map[string]bool)
			_ = am.processSecondaryBom(tt.secondary)

			// Ensure proper DESCRIBES relationships
			am.ensurePrimaryDescribes()

			// Count DESCRIBES relationships
			describesCount := 0
			var describedPkgID string
			for _, rel := range am.primary.Relationships {
				if rel.Relationship == common.TypeRelationshipDescribe {
					describesCount++
					describedPkgID = am.docElementIDToString(rel.RefB)
				}
			}

			// Assertions
			if describesCount != tt.expectedDescribesCount {
				t.Errorf("DESCRIBES count mismatch: expected %d, got %d", tt.expectedDescribesCount, describesCount)
			}

			if tt.shouldHaveDescribes {
				if describedPkgID != tt.expectedDescribedPkgID {
					t.Errorf("Wrong package described: expected %s, got %s", tt.expectedDescribedPkgID, describedPkgID)
				}
			}

			// Ensure no DESCRIBES from secondary were copied
			for _, rel := range am.primary.Relationships {
				if rel.Relationship == common.TypeRelationshipDescribe {
					refB := am.docElementIDToString(rel.RefB)
					// Should not describe any secondary package
					if refB == "SPDXRef-SecPkg" || refB == "SPDXRef-SecPkg1" || refB == "SPDXRef-SecPkg2" {
						t.Errorf("Secondary DESCRIBES should not be copied: found %s", refB)
					}
				}
			}
		})
	}
}

func TestFindPrimaryPackage(t *testing.T) {
	tests := []struct {
		name           string
		doc            *spdx.Document
		expectedPkgID  string
		expectedFound  bool
	}{
		{
			name: "Find package with DESCRIBES relationship",
			doc: &spdx.Document{
				SPDXIdentifier: "DOCUMENT",
				Packages: []*spdx.Package{
					{
						PackageName:           "Pkg1",
						PackageSPDXIdentifier: "SPDXRef-Pkg1",
					},
					{
						PackageName:           "Pkg2",
						PackageSPDXIdentifier: "SPDXRef-Pkg2",
					},
				},
				Relationships: []*spdx.Relationship{
					{
						RefA:         common.MakeDocElementID("", "DOCUMENT"),
						RefB:         common.MakeDocElementID("", "SPDXRef-Pkg2"),
						Relationship: common.TypeRelationshipDescribe,
					},
				},
			},
			expectedPkgID: "SPDXRef-Pkg2",
			expectedFound: true,
		},
		{
			name: "Single package without DESCRIBES",
			doc: &spdx.Document{
				SPDXIdentifier: "DOCUMENT",
				Packages: []*spdx.Package{
					{
						PackageName:           "SinglePkg",
						PackageSPDXIdentifier: "SPDXRef-SinglePkg",
					},
				},
				Relationships: []*spdx.Relationship{},
			},
			expectedPkgID: "SPDXRef-SinglePkg",
			expectedFound: true,
		},
		{
			name: "Multiple packages without DESCRIBES - fallback to first",
			doc: &spdx.Document{
				SPDXIdentifier: "DOCUMENT",
				Packages: []*spdx.Package{
					{
						PackageName:           "FirstPkg",
						PackageSPDXIdentifier: "SPDXRef-FirstPkg",
					},
					{
						PackageName:           "SecondPkg",
						PackageSPDXIdentifier: "SPDXRef-SecondPkg",
					},
				},
				Relationships: []*spdx.Relationship{},
			},
			expectedPkgID: "SPDXRef-FirstPkg",
			expectedFound: true,
		},
		{
			name: "No packages",
			doc: &spdx.Document{
				SPDXIdentifier: "DOCUMENT",
				Packages:       []*spdx.Package{},
				Relationships:  []*spdx.Relationship{},
			},
			expectedPkgID: "",
			expectedFound: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			ms := &MergeSettings{
				Ctx: &ctx,
			}
			am := newAugmentMerge(ms)
			am.primary = tt.doc

			pkg := am.findPrimaryPackage()

			if tt.expectedFound {
				if pkg == nil {
					t.Error("Expected to find primary package, but got nil")
				} else if string(pkg.PackageSPDXIdentifier) != tt.expectedPkgID {
					t.Errorf("Expected package ID %s, got %s", tt.expectedPkgID, string(pkg.PackageSPDXIdentifier))
				}
			} else {
				if pkg != nil {
					t.Error("Expected no primary package, but found one")
				}
			}
		})
	}
}