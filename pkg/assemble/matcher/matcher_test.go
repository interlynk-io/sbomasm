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

package matcher

import (
	"testing"

	cydx "github.com/CycloneDX/cyclonedx-go"
	"github.com/spdx/tools-golang/spdx"
)

// Mock component for testing
type mockComponent struct {
	purl    string
	cpe     string
	name    string
	version string
	typ     string
}

func (m *mockComponent) GetPurl() string    { return m.purl }
func (m *mockComponent) GetCPE() string     { return m.cpe }
func (m *mockComponent) GetName() string    { return m.name }
func (m *mockComponent) GetVersion() string { return m.version }
func (m *mockComponent) GetType() string    { return m.typ }
func (m *mockComponent) IsCDX() bool        { return false }
func (m *mockComponent) IsSPDX() bool       { return false }
func (m *mockComponent) GetOriginal() interface{} { return nil }

func TestPurlMatcher(t *testing.T) {
	tests := []struct {
		name          string
		primary       Component
		secondary     Component
		strictVersion bool
		expectMatch   bool
		confidence    int
	}{
		{
			name: "exact purl match",
			primary: &mockComponent{
				purl: "pkg:maven/org.apache.commons/commons-lang3@3.12.0",
			},
			secondary: &mockComponent{
				purl: "pkg:maven/org.apache.commons/commons-lang3@3.12.0",
			},
			strictVersion: true,
			expectMatch:   true,
			confidence:    100,
		},
		{
			name: "purl match ignoring version",
			primary: &mockComponent{
				purl: "pkg:maven/org.apache.commons/commons-lang3@3.12.0",
			},
			secondary: &mockComponent{
				purl: "pkg:maven/org.apache.commons/commons-lang3@3.13.0",
			},
			strictVersion: false,
			expectMatch:   true,
			confidence:    100,
		},
		{
			name: "different purl no match",
			primary: &mockComponent{
				purl: "pkg:maven/org.apache.commons/commons-lang3@3.12.0",
			},
			secondary: &mockComponent{
				purl: "pkg:maven/org.apache.commons/commons-io@2.11.0",
			},
			strictVersion: false,
			expectMatch:   false,
			confidence:    0,
		},
		{
			name: "case insensitive match",
			primary: &mockComponent{
				purl: "pkg:maven/org.apache.commons/Commons-Lang3@3.12.0",
			},
			secondary: &mockComponent{
				purl: "pkg:maven/org.apache.commons/commons-lang3@3.12.0",
			},
			strictVersion: true,
			expectMatch:   true,
			confidence:    100,
		},
		{
			name: "missing purl no match",
			primary: &mockComponent{
				purl: "",
			},
			secondary: &mockComponent{
				purl: "pkg:maven/org.apache.commons/commons-lang3@3.12.0",
			},
			strictVersion: false,
			expectMatch:   false,
			confidence:    0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matcher := NewPurlMatcher(tt.strictVersion)
			
			matched := matcher.Match(tt.primary, tt.secondary)
			if matched != tt.expectMatch {
				t.Errorf("expected match=%v, got %v", tt.expectMatch, matched)
			}
			
			confidence := matcher.MatchConfidence(tt.primary, tt.secondary)
			if confidence != tt.confidence {
				t.Errorf("expected confidence=%d, got %d", tt.confidence, confidence)
			}
		})
	}
}

func TestCPEMatcher(t *testing.T) {
	tests := []struct {
		name          string
		primary       Component
		secondary     Component
		ignoreVersion bool
		expectMatch   bool
		confidence    int
	}{
		{
			name: "exact CPE 2.3 match",
			primary: &mockComponent{
				cpe: "cpe:2.3:a:apache:commons_lang3:3.12.0:*:*:*:*:*:*:*",
			},
			secondary: &mockComponent{
				cpe: "cpe:2.3:a:apache:commons_lang3:3.12.0:*:*:*:*:*:*:*",
			},
			ignoreVersion: false,
			expectMatch:   true,
			confidence:    90,
		},
		{
			name: "CPE match ignoring version",
			primary: &mockComponent{
				cpe: "cpe:2.3:a:apache:commons_lang3:3.12.0:*:*:*:*:*:*:*",
			},
			secondary: &mockComponent{
				cpe: "cpe:2.3:a:apache:commons_lang3:3.13.0:*:*:*:*:*:*:*",
			},
			ignoreVersion: true,
			expectMatch:   true,
			confidence:    90,
		},
		{
			name: "CPE 2.2 to 2.3 conversion match",
			primary: &mockComponent{
				cpe: "cpe:/a:apache:commons_lang3:3.12.0",
			},
			secondary: &mockComponent{
				cpe: "cpe:2.3:a:apache:commons_lang3:3.12.0:*:*:*:*:*:*:*",
			},
			ignoreVersion: false,
			expectMatch:   true,
			confidence:    90,
		},
		{
			name: "different CPE no match",
			primary: &mockComponent{
				cpe: "cpe:2.3:a:apache:commons_lang3:3.12.0:*:*:*:*:*:*:*",
			},
			secondary: &mockComponent{
				cpe: "cpe:2.3:a:apache:commons_io:2.11.0:*:*:*:*:*:*:*",
			},
			ignoreVersion: true,
			expectMatch:   false,
			confidence:    0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matcher := NewCPEMatcher(tt.ignoreVersion)
			
			matched := matcher.Match(tt.primary, tt.secondary)
			if matched != tt.expectMatch {
				t.Errorf("expected match=%v, got %v", tt.expectMatch, matched)
			}
			
			confidence := matcher.MatchConfidence(tt.primary, tt.secondary)
			if confidence != tt.confidence {
				t.Errorf("expected confidence=%d, got %d", tt.confidence, confidence)
			}
		})
	}
}

func TestNameVersionMatcher(t *testing.T) {
	tests := []struct {
		name        string
		primary     Component
		secondary   Component
		fuzzyMatch  bool
		typeMatch   bool
		expectMatch bool
		minConfidence int
	}{
		{
			name: "exact name and version match",
			primary: &mockComponent{
				name:    "commons-lang3",
				version: "3.12.0",
				typ:     "library",
			},
			secondary: &mockComponent{
				name:    "commons-lang3",
				version: "3.12.0",
				typ:     "library",
			},
			fuzzyMatch:  false,
			typeMatch:   true,
			expectMatch: true,
			minConfidence: 80,
		},
		{
			name: "normalized version match (v prefix)",
			primary: &mockComponent{
				name:    "commons-lang3",
				version: "v3.12.0",
			},
			secondary: &mockComponent{
				name:    "commons-lang3",
				version: "3.12.0",
			},
			fuzzyMatch:  false,
			typeMatch:   false,
			expectMatch: true,
			minConfidence: 70,
		},
		{
			name: "normalized name match (underscore vs dash)",
			primary: &mockComponent{
				name:    "commons_lang3",
				version: "3.12.0",
			},
			secondary: &mockComponent{
				name:    "commons-lang3",
				version: "3.12.0",
			},
			fuzzyMatch:  false,
			typeMatch:   false,
			expectMatch: true,
			minConfidence: 70,
		},
		{
			name: "fuzzy name match",
			primary: &mockComponent{
				name:    "apache-commons-lang3",
				version: "3.12.0",
			},
			secondary: &mockComponent{
				name:    "commons-lang3",
				version: "3.12.0",
			},
			fuzzyMatch:  true,
			typeMatch:   false,
			expectMatch: true,
			minConfidence: 60,
		},
		{
			name: "type mismatch with typeMatch enabled",
			primary: &mockComponent{
				name:    "commons-lang3",
				version: "3.12.0",
				typ:     "library",
			},
			secondary: &mockComponent{
				name:    "commons-lang3",
				version: "3.12.0",
				typ:     "application",
			},
			fuzzyMatch:  false,
			typeMatch:   true,
			expectMatch: false,
			minConfidence: 0,
		},
		{
			name: "different version no match",
			primary: &mockComponent{
				name:    "commons-lang3",
				version: "3.12.0",
			},
			secondary: &mockComponent{
				name:    "commons-lang3",
				version: "3.13.0",
			},
			fuzzyMatch:  false,
			typeMatch:   false,
			expectMatch: false,
			minConfidence: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matcher := NewNameVersionMatcher(tt.fuzzyMatch, tt.typeMatch)
			
			matched := matcher.Match(tt.primary, tt.secondary)
			if matched != tt.expectMatch {
				t.Errorf("expected match=%v, got %v", tt.expectMatch, matched)
			}
			
			confidence := matcher.MatchConfidence(tt.primary, tt.secondary)
			if tt.expectMatch && confidence < tt.minConfidence {
				t.Errorf("expected confidence>=%d, got %d", tt.minConfidence, confidence)
			}
			if !tt.expectMatch && confidence != 0 {
				t.Errorf("expected confidence=0 for no match, got %d", confidence)
			}
		})
	}
}

func TestUnifiedComponent(t *testing.T) {
	t.Run("CDX component", func(t *testing.T) {
		cdxComp := &cydx.Component{
			Name:       "test-component",
			Version:    "1.0.0",
			Type:       cydx.ComponentTypeLibrary,
			PackageURL: "pkg:maven/test/test-component@1.0.0",
			CPE:        "cpe:2.3:a:test:test-component:1.0.0:*:*:*:*:*:*:*",
		}
		
		unified := NewCDXComponent(cdxComp)
		
		if !unified.IsCDX() {
			t.Error("expected IsCDX() to be true")
		}
		if unified.IsSPDX() {
			t.Error("expected IsSPDX() to be false")
		}
		if unified.GetName() != "test-component" {
			t.Errorf("expected name='test-component', got %s", unified.GetName())
		}
		if unified.GetVersion() != "1.0.0" {
			t.Errorf("expected version='1.0.0', got %s", unified.GetVersion())
		}
		if unified.GetType() != "library" {
			t.Errorf("expected type='library', got %s", unified.GetType())
		}
		if unified.GetPurl() != "pkg:maven/test/test-component@1.0.0" {
			t.Errorf("unexpected purl: %s", unified.GetPurl())
		}
	})

	t.Run("SPDX package", func(t *testing.T) {
		spdxPkg := &spdx.Package{
			PackageName:    "test-package",
			PackageVersion: "2.0.0",
			PrimaryPackagePurpose: "APPLICATION",
			PackageExternalReferences: []*spdx.PackageExternalReference{
				{
					Category: "PACKAGE-MANAGER",
					RefType:  "purl",
					Locator:  "pkg:npm/test-package@2.0.0",
				},
				{
					RefType: "cpe23Type",
					Locator: "cpe:2.3:a:test:test-package:2.0.0:*:*:*:*:*:*:*",
				},
			},
		}
		
		unified := NewSPDXComponent(spdxPkg)
		
		if unified.IsCDX() {
			t.Error("expected IsCDX() to be false")
		}
		if !unified.IsSPDX() {
			t.Error("expected IsSPDX() to be true")
		}
		if unified.GetName() != "test-package" {
			t.Errorf("expected name='test-package', got %s", unified.GetName())
		}
		if unified.GetVersion() != "2.0.0" {
			t.Errorf("expected version='2.0.0', got %s", unified.GetVersion())
		}
		if unified.GetType() != "application" {
			t.Errorf("expected type='application', got %s", unified.GetType())
		}
		if unified.GetPurl() != "pkg:npm/test-package@2.0.0" {
			t.Errorf("unexpected purl: %s", unified.GetPurl())
		}
		if unified.GetCPE() != "cpe:2.3:a:test:test-package:2.0.0:*:*:*:*:*:*:*" {
			t.Errorf("unexpected cpe: %s", unified.GetCPE())
		}
	})
}

func TestComponentIndex(t *testing.T) {
	components := []Component{
		&mockComponent{
			name:    "component1",
			version: "1.0.0",
			purl:    "pkg:maven/test/component1@1.0.0",
			cpe:     "cpe:2.3:a:test:component1:1.0.0:*:*:*:*:*:*:*",
		},
		&mockComponent{
			name:    "component2",
			version: "2.0.0",
			purl:    "pkg:npm/component2@2.0.0",
		},
		&mockComponent{
			name:    "component3",
			version: "1.0.0",
			cpe:     "cpe:2.3:a:test:component3:1.0.0:*:*:*:*:*:*:*",
		},
	}
	
	index := BuildIndex(components)
	
	t.Run("find by purl", func(t *testing.T) {
		matcher := NewPurlMatcher(true)
		searchComp := &mockComponent{
			purl: "pkg:maven/test/component1@1.0.0",
		}
		
		matches := index.FindMatches(searchComp, matcher)
		if len(matches) != 1 {
			t.Errorf("expected 1 match, got %d", len(matches))
		}
		if len(matches) > 0 && matches[0].Primary.GetName() != "component1" {
			t.Errorf("expected to match component1, got %s", matches[0].Primary.GetName())
		}
	})
	
	t.Run("find by name-version", func(t *testing.T) {
		matcher := NewNameVersionMatcher(false, false)
		searchComp := &mockComponent{
			name:    "component2",
			version: "2.0.0",
		}
		
		matches := index.FindMatches(searchComp, matcher)
		if len(matches) != 1 {
			t.Errorf("expected 1 match, got %d", len(matches))
		}
	})
	
	t.Run("find best match", func(t *testing.T) {
		matcher := NewCPEMatcher(false)
		searchComp := &mockComponent{
			cpe: "cpe:2.3:a:test:component3:1.0.0:*:*:*:*:*:*:*",
		}
		
		best := index.FindBestMatch(searchComp, matcher)
		if best == nil {
			t.Error("expected to find a match")
		}
		if best != nil && best.Primary.GetName() != "component3" {
			t.Errorf("expected to match component3, got %s", best.Primary.GetName())
		}
	})
	
	t.Run("no match", func(t *testing.T) {
		matcher := NewPurlMatcher(true)
		searchComp := &mockComponent{
			purl: "pkg:maven/nonexistent/component@1.0.0",
		}
		
		matches := index.FindMatches(searchComp, matcher)
		if len(matches) != 0 {
			t.Errorf("expected no matches, got %d", len(matches))
		}
	})
}

func TestMatcherFactory(t *testing.T) {
	factory := NewDefaultMatcherFactory(nil)
	
	t.Run("create purl matcher", func(t *testing.T) {
		matcher, err := factory.GetMatcher("purl")
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if matcher.Strategy() != "purl" {
			t.Errorf("expected purl strategy, got %s", matcher.Strategy())
		}
	})
	
	t.Run("create cpe matcher", func(t *testing.T) {
		matcher, err := factory.GetMatcher("cpe")
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if matcher.Strategy() != "cpe" {
			t.Errorf("expected cpe strategy, got %s", matcher.Strategy())
		}
	})
	
	t.Run("create name-version matcher", func(t *testing.T) {
		matcher, err := factory.GetMatcher("name-version")
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if matcher.Strategy() != "name-version" {
			t.Errorf("expected name-version strategy, got %s", matcher.Strategy())
		}
	})
	
	t.Run("unknown strategy error", func(t *testing.T) {
		_, err := factory.GetMatcher("unknown")
		if err == nil {
			t.Error("expected error for unknown strategy")
		}
	})
}