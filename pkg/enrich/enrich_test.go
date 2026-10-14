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

package enrich

import (
	"testing"

	spdx3 "github.com/interlynk-io/spdx-zen/model/v3.0.1"
	"github.com/interlynk-io/spdx-zen/parse"
)

func TestHasExistingLicense(t *testing.T) {
	doc := &parse.Document{
		Relationships: []*spdx3.Relationship{
			{
				RelationshipType: spdx3.RelationshipTypeHasConcludedLicense,
				From:             spdx3.Element{SpdxID: "https://example.org/pkg1"},
				To:               []spdx3.Element{{SpdxID: "https://example.org/lic-mit"}},
			},
			{
				RelationshipType: spdx3.RelationshipTypeDependsOn,
				From:             spdx3.Element{SpdxID: "https://example.org/pkg1"},
				To:               []spdx3.Element{{SpdxID: "https://example.org/pkg2"}},
			},
		},
	}

	if !hasExistingLicense(doc, "https://example.org/pkg1") {
		t.Error("expected hasExistingLicense to return true for pkg1")
	}

	if hasExistingLicense(doc, "https://example.org/pkg2") {
		t.Error("expected hasExistingLicense to return false for pkg2")
	}
}

func TestGetPurlSPDX3(t *testing.T) {
	pkg := &spdx3.Package{}
	pkg.ExternalIdentifier = []spdx3.ExternalIdentifier{
		{
			ExternalIdentifierType: spdx3.ExternalIdentifierTypePackageUrl,
			Identifier:             "pkg:npm/my-app@1.0.0",
		},
		{
			ExternalIdentifierType: spdx3.ExternalIdentifierTypeCpe23,
			Identifier:             "cpe:2.3:a:acme:my-app:1.0.0",
		},
	}

	got := getPurl(pkg)
	want := "pkg:npm/my-app@1.0.0"
	if got != want {
		t.Errorf("getPurl() = %q, want %q", got, want)
	}
}

func TestGetPurlSPDX3NoPurl(t *testing.T) {
	pkg := &spdx3.Package{}
	pkg.ExternalIdentifier = []spdx3.ExternalIdentifier{
		{
			ExternalIdentifierType: spdx3.ExternalIdentifierTypeCpe23,
			Identifier:             "cpe:2.3:a:acme:my-app:1.0.0",
		},
	}

	got := getPurl(pkg)
	if got != "" {
		t.Errorf("getPurl() = %q, want empty", got)
	}
}

func TestCreateSimpleLicensingText(t *testing.T) {
	doc := &parse.Document{
		SpdxDocument: &spdx3.SpdxDocument{},
		CreationInfo: &spdx3.CreationInfo{
			SpecVersion: "3.0.1",
		},
	}
	doc.SpdxDocument.SpdxID = "https://example.org/doc1"

	lic := createSimpleLicensingText(doc, "MIT")

	if lic.Name != "MIT" {
		t.Errorf("Name = %q, want MIT", lic.Name)
	}
	if lic.SpdxID != "https://example.org/doc1/lic-MIT" {
		t.Errorf("SpdxID = %q, want https://example.org/doc1/lic-MIT", lic.SpdxID)
	}
	if lic.CreationInfo.SpecVersion != "3.0.1" {
		t.Errorf("CreationInfo.SpecVersion = %q, want 3.0.1", lic.CreationInfo.SpecVersion)
	}
}

func TestCreateHasConcludedLicenseRelationship(t *testing.T) {
	doc := &parse.Document{
		SpdxDocument: &spdx3.SpdxDocument{},
		CreationInfo: &spdx3.CreationInfo{
			SpecVersion: "3.0.1",
		},
	}
	doc.SpdxDocument.SpdxID = "https://example.org/doc1"

	rel := createHasConcludedLicenseRelationship(doc, "https://example.org/pkg1", "https://example.org/lic-mit")

	if rel.RelationshipType != spdx3.RelationshipTypeHasConcludedLicense {
		t.Errorf("RelationshipType = %q, want hasConcludedLicense", rel.RelationshipType)
	}
	if rel.From.SpdxID != "https://example.org/pkg1" {
		t.Errorf("From.SpdxID = %q, want https://example.org/pkg1", rel.From.SpdxID)
	}
	if len(rel.To) != 1 || rel.To[0].SpdxID != "https://example.org/lic-mit" {
		t.Errorf("To = %v, want [https://example.org/lic-mit]", rel.To)
	}
	if rel.CreationInfo.SpecVersion != "3.0.1" {
		t.Errorf("CreationInfo.SpecVersion = %q, want 3.0.1", rel.CreationInfo.SpecVersion)
	}
}

func TestAddLicenseToDocument(t *testing.T) {
	doc := &parse.Document{
		ElementsByID:             make(map[string]interface{}),
		SimpleLicensingTextsByID: make(map[string]*spdx3.SimpleLicensingText),
		RelationshipsFromIndex:   make(map[string][]*spdx3.Relationship),
		RelationshipsToIndex:     make(map[string][]*spdx3.Relationship),
	}

	lic := &spdx3.SimpleLicensingText{
		Element: spdx3.Element{
			SpdxID: "https://example.org/lic-mit",
			Name:   "MIT",
		},
	}
	rel := &spdx3.Relationship{
		RelationshipType: spdx3.RelationshipTypeHasConcludedLicense,
		From:             spdx3.Element{SpdxID: "https://example.org/pkg1"},
		To:               []spdx3.Element{{SpdxID: "https://example.org/lic-mit"}},
	}

	addLicenseToDocument(doc, lic, rel)

	// Check SimpleLicensingTexts slice
	if len(doc.SimpleLicensingTexts) != 1 {
		t.Errorf("SimpleLicensingTexts len = %d, want 1", len(doc.SimpleLicensingTexts))
	}

	// Check ElementsByID
	if doc.ElementsByID["https://example.org/lic-mit"] == nil {
		t.Error("ElementsByID missing license")
	}

	// Check SimpleLicensingTextsByID
	if doc.SimpleLicensingTextsByID["https://example.org/lic-mit"] == nil {
		t.Error("SimpleLicensingTextsByID missing license")
	}

	// Check Relationships slice
	if len(doc.Relationships) != 1 {
		t.Errorf("Relationships len = %d, want 1", len(doc.Relationships))
	}

	// Check RelationshipsFromIndex
	fromRels := doc.RelationshipsFromIndex["https://example.org/pkg1"]
	if len(fromRels) != 1 {
		t.Errorf("RelationshipsFromIndex[from] len = %d, want 1", len(fromRels))
	}

	// Check RelationshipsToIndex
	toRels := doc.RelationshipsToIndex["https://example.org/lic-mit"]
	if len(toRels) != 1 {
		t.Errorf("RelationshipsToIndex[to] len = %d, want 1", len(toRels))
	}
}

func TestSanitizeLicenseName(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"MIT", "MIT"},
		{"Apache-2.0", "Apache-2.0"},
		{"GPL 2.0", "GPL-2.0"},
		{"MIT+", "MITplus"},
	}
	for _, tt := range tests {
		got := sanitizeLicenseName(tt.input)
		if got != tt.want {
			t.Errorf("sanitizeLicenseName(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestSanitizeForID(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"https://example.org/pkg1", "pkg1"},
		{"pkg1", "pkg1"},
	}
	for _, tt := range tests {
		got := sanitizeForID(tt.input)
		if got != tt.want {
			t.Errorf("sanitizeForID(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
