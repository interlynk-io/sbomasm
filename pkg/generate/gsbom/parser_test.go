// Copyright 2026 Interlynk.io
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package gsbom

import (
	"os"
	"strings"
	"testing"
)

// Common JSON component templates
var (
	validMinimalComponentJSON = `{
		"schema": "interlynk/component-manifest/v1",
		"components": [{
			"name": "mylib",
			"version": "1.0.0",
			"type": "library"
		}]
	}`

	validMinimalComponentExpected = Component{
		Name:    "mylib",
		Version: "1.0.0",
		Type:    "library",
	}

	// Helper to build component JSON with custom type
	componentWithType = func(compType string) string {
		return `{
			"schema": "interlynk/component-manifest/v1",
			"components": [{
				"name": "mylib",
				"version": "1.0.0",
				"type": "` + compType + `"
			}]
		}`
	}

	// Helper to build component JSON with name/version
	componentWithNameVersion = func(name, version string) string {
		return `{
			"schema": "interlynk/component-manifest/v1",
			"components": [{
				"name": "` + name + `",
				"version": "` + version + `",
				"type": "library"
			}]
		}`
	}
)

func TestParseJSONComponents(t *testing.T) {
	tests := []struct {
		name          string
		jsonContent   string
		wantError     bool
		errorContains string
		expected      []Component
	}{
		// ============ REQUIRED FIELDS TESTS ============
		{
			name:        "valid minimal component",
			jsonContent: validMinimalComponentJSON,
			wantError:   false,
			expected:    []Component{validMinimalComponentExpected},
		},
		{
			name:          "missing name field",
			jsonContent:   componentWithNameVersion("", "1.0.0"),
			wantError:     true,
			errorContains: "name is required",
		},
		{
			name:          "missing version field",
			jsonContent:   componentWithNameVersion("mylib", ""),
			wantError:     true,
			errorContains: "version is required",
		},
		{
			name:          "whitespace-only name",
			jsonContent:   componentWithNameVersion("   ", "1.0.0"),
			wantError:     true,
			errorContains: "name is required",
		},
		{
			name:          "whitespace-only version",
			jsonContent:   componentWithNameVersion("mylib", "   "),
			wantError:     true,
			errorContains: "version is required",
		},
		{
			name: "missing type field - optional",
			jsonContent: `{
				"schema": "interlynk/component-manifest/v1",
				"components": [{
					"name": "mylib",
					"version": "1.0.0"
				}]
			}`,
			wantError: false,
			expected: []Component{{
				Name:    "mylib",
				Version: "1.0.0",
				Type:    "",
			}},
		},

		// ============ TYPE VALIDATION ============
		{
			name:        "valid type - library",
			jsonContent: componentWithType("library"),
			wantError:   false,
			expected:    []Component{{Name: "mylib", Version: "1.0.0", Type: "library"}},
		},
		{
			name:        "valid type - application",
			jsonContent: componentWithType("application"),
			wantError:   false,
			expected:    []Component{{Name: "mylib", Version: "1.0.0", Type: "application"}},
		},
		{
			name:        "valid type - framework",
			jsonContent: componentWithType("framework"),
			wantError:   false,
			expected:    []Component{{Name: "mylib", Version: "1.0.0", Type: "framework"}},
		},
		{
			name:        "valid type - container",
			jsonContent: componentWithType("container"),
			wantError:   false,
			expected:    []Component{{Name: "mylib", Version: "1.0.0", Type: "container"}},
		},
		{
			name:        "valid type - operating-system",
			jsonContent: componentWithType("operating-system"),
			wantError:   false,
			expected:    []Component{{Name: "mylib", Version: "1.0.0", Type: "operating-system"}},
		},
		{
			name:        "valid type - device",
			jsonContent: componentWithType("device"),
			wantError:   false,
			expected:    []Component{{Name: "mylib", Version: "1.0.0", Type: "device"}},
		},
		{
			name:        "valid type - firmware",
			jsonContent: componentWithType("firmware"),
			wantError:   false,
			expected:    []Component{{Name: "mylib", Version: "1.0.0", Type: "firmware"}},
		},
		{
			name:        "valid type - file",
			jsonContent: componentWithType("file"),
			wantError:   false,
			expected:    []Component{{Name: "mylib", Version: "1.0.0", Type: "file"}},
		},
		{
			name:        "valid type - platform",
			jsonContent: componentWithType("platform"),
			wantError:   false,
			expected:    []Component{{Name: "mylib", Version: "1.0.0", Type: "platform"}},
		},
		{
			name:        "valid type - device-driver",
			jsonContent: componentWithType("device-driver"),
			wantError:   false,
			expected:    []Component{{Name: "mylib", Version: "1.0.0", Type: "device-driver"}},
		},
		{
			name:        "valid type - machine-learning-model",
			jsonContent: componentWithType("machine-learning-model"),
			wantError:   false,
			expected:    []Component{{Name: "mylib", Version: "1.0.0", Type: "machine-learning-model"}},
		},
		{
			name:        "valid type - data",
			jsonContent: componentWithType("data"),
			wantError:   false,
			expected:    []Component{{Name: "mylib", Version: "1.0.0", Type: "data"}},
		},
		{
			name:          "invalid type value",
			jsonContent:   componentWithType("invalid-type"),
			wantError:     true,
			errorContains: "invalid type",
		},

		// ============ SANITIZATION TESTS ============
		{
			name: "sanitized fields with whitespace",
			jsonContent: `{
				"schema": "interlynk/component-manifest/v1",
				"components": [{
					"name": "  mylib  ",
					"version": "  1.0.0  ",
					"type": "  library  ",
					"description": "  My Library  ",
					"purl": "  pkg:generic/mylib@1.0.0  ",
					"cpe": "  cpe:2.3:a:mylib:1.0.0  "
				}]
			}`,
			wantError: false,
			expected: []Component{{
				Name:        "mylib",
				Version:     "1.0.0",
				Type:        "library",
				Description: "My Library",
				PURL:        "pkg:generic/mylib@1.0.0",
				CPE:         "cpe:2.3:a:mylib:1.0.0",
			}},
		},
		{
			name: "sanitized supplier fields",
			jsonContent: `{
				"schema": "interlynk/component-manifest/v1",
				"components": [{
					"name": "mylib",
					"version": "1.0.0",
					"type": "library",
					"supplier": {
						"name": "  Acme Corp  ",
						"email": "  security@acme.example  ",
						"url": "  https://acme.example  "
					}
				}]
			}`,
			wantError: false,
			expected: []Component{{
				Name:    "mylib",
				Version: "1.0.0",
				Type:    "library",
				Supplier: Supplier{
					Name:  "Acme Corp",
					Email: "security@acme.example",
					URL:   "https://acme.example",
				},
			}},
		},
		{
			name: "sanitized tags",
			jsonContent: `{
				"schema": "interlynk/component-manifest/v1",
				"components": [{
					"name": "mylib",
					"version": "1.0.0",
					"type": "library",
					"tags": ["  frontend  ", "  critical  "]
				}]
			}`,
			wantError: false,
			expected: []Component{{
				Name:    "mylib",
				Version: "1.0.0",
				Type:    "library",
				Tags:    []string{"frontend", "critical"},
			}},
		},
		{
			name: "sanitized depends-on",
			jsonContent: `{
				"schema": "interlynk/component-manifest/v1",
				"components": [{
					"name": "mylib",
					"version": "1.0.0",
					"type": "library",
					"depends-on": ["  dep1@1.0.0  ", "  dep2@2.0.0  "]
				}]
			}`,
			wantError: false,
			expected: []Component{{
				Name:      "mylib",
				Version:   "1.0.0",
				Type:      "library",
				DependsOn: []string{"dep1@1.0.0", "dep2@2.0.0"},
			}},
		},

		// ============ LICENSE FIELD TESTS ============
		{
			name: "license as string expression",
			jsonContent: `{
				"schema": "interlynk/component-manifest/v1",
				"components": [{
					"name": "mylib",
					"version": "1.0.0",
					"type": "library",
					"license": "MIT OR Apache-2.0"
				}]
			}`,
			wantError: false,
			expected: []Component{{
				Name:    "mylib",
				Version: "1.0.0",
				Type:    "library",
				License: LicenseField{Expression: "MIT OR Apache-2.0"},
			}},
		},
		{
			name: "license as simple string ID",
			jsonContent: `{
				"schema": "interlynk/component-manifest/v1",
				"components": [{
					"name": "mylib",
					"version": "1.0.0",
					"type": "library",
					"license": "MIT"
				}]
			}`,
			wantError: false,
			expected: []Component{{
				Name:    "mylib",
				Version: "1.0.0",
				Type:    "library",
				License: LicenseField{Expression: "MIT"},
			}},
		},
		{
			name: "license as object with id",
			jsonContent: `{
				"schema": "interlynk/component-manifest/v1",
				"components": [{
					"name": "mylib",
					"version": "1.0.0",
					"type": "library",
					"license": {"id": "MIT"}
				}]
			}`,
			wantError: false,
			expected: []Component{{
				Name:    "mylib",
				Version: "1.0.0",
				Type:    "library",
				License: LicenseField{ID: "MIT"},
			}},
		},
		{
			name: "license as object with id and text",
			jsonContent: `{
				"schema": "interlynk/component-manifest/v1",
				"components": [{
					"name": "mylib",
					"version": "1.0.0",
					"type": "library",
					"license": {"id": "MIT", "text": "Permission is hereby granted..."}
				}]
			}`,
			wantError: false,
			expected: []Component{{
				Name:    "mylib",
				Version: "1.0.0",
				Type:    "library",
				License: LicenseField{ID: "MIT", Text: "Permission is hereby granted..."},
			}},
		},
		{
			name: "license as object with file",
			jsonContent: `{
				"schema": "interlynk/component-manifest/v1",
				"components": [{
					"name": "mylib",
					"version": "1.0.0",
					"type": "library",
					"license": {"id": "MIT", "file": "./LICENSE"}
				}]
			}`,
			wantError: false,
			expected: []Component{{
				Name:    "mylib",
				Version: "1.0.0",
				Type:    "library",
				License: LicenseField{ID: "MIT", File: "./LICENSE"},
			}},
		},
		{
			name: "empty license field",
			jsonContent: `{
				"schema": "interlynk/component-manifest/v1",
				"components": [{
					"name": "mylib",
					"version": "1.0.0",
					"type": "library",
					"license": ""
				}]
			}`,
			wantError: false,
			expected: []Component{{
				Name:    "mylib",
				Version: "1.0.0",
				Type:    "library",
			}},
		},
		{
			name: "null license field",
			jsonContent: `{
				"schema": "interlynk/component-manifest/v1",
				"components": [{
					"name": "mylib",
					"version": "1.0.0",
					"type": "library",
					"license": null
				}]
			}`,
			wantError: false,
			expected: []Component{{
				Name:    "mylib",
				Version: "1.0.0",
				Type:    "library",
			}},
		},

		// ============ HASH/CHECKSUM TESTS ============
		{
			name: "valid SHA-256 hash",
			jsonContent: `{
				"schema": "interlynk/component-manifest/v1",
				"components": [{
					"name": "mylib",
					"version": "1.0.0",
					"type": "library",
					"hashes": [{
						"algorithm": "SHA-256",
						"value": "abc123"
					}]
				}]
			}`,
			wantError: false,
			expected: []Component{{
				Name:    "mylib",
				Version: "1.0.0",
				Type:    "library",
				Hashes:  []Hash{{Algorithm: "SHA-256", Value: "abc123"}},
			}},
		},
		{
			name: "valid SHA-1 hash",
			jsonContent: `{
				"schema": "interlynk/component-manifest/v1",
				"components": [{
					"name": "mylib",
					"version": "1.0.0",
					"type": "library",
					"hashes": [{
						"algorithm": "SHA-1",
						"value": "def456"
					}]
				}]
			}`,
			wantError: false,
			expected: []Component{{
				Name:    "mylib",
				Version: "1.0.0",
				Type:    "library",
				Hashes:  []Hash{{Algorithm: "SHA-1", Value: "def456"}},
			}},
		},
		{
			name: "valid MD5 hash",
			jsonContent: `{
				"schema": "interlynk/component-manifest/v1",
				"components": [{
					"name": "mylib",
					"version": "1.0.0",
					"type": "library",
					"hashes": [{
						"algorithm": "MD5",
						"value": "789abc"
					}]
				}]
			}`,
			wantError: false,
			expected: []Component{{
				Name:    "mylib",
				Version: "1.0.0",
				Type:    "library",
				Hashes:  []Hash{{Algorithm: "MD5", Value: "789abc"}},
			}},
		},
		{
			name: "multiple hashes",
			jsonContent: `{
				"schema": "interlynk/component-manifest/v1",
				"components": [{
					"name": "mylib",
					"version": "1.0.0",
					"type": "library",
					"hashes": [
						{"algorithm": "SHA-256", "value": "abc123"},
						{"algorithm": "SHA-1", "value": "def456"},
						{"algorithm": "MD5", "value": "789abc"}
					]
				}]
			}`,
			wantError: false,
			expected: []Component{{
				Name:    "mylib",
				Version: "1.0.0",
				Type:    "library",
				Hashes: []Hash{
					{Algorithm: "SHA-256", Value: "abc123"},
					{Algorithm: "SHA-1", Value: "def456"},
					{Algorithm: "MD5", Value: "789abc"},
				},
			}},
		},
		{
			name: "empty hash value - preserved",
			jsonContent: `{
				"schema": "interlynk/component-manifest/v1",
				"components": [{
					"name": "mylib",
					"version": "1.0.0",
					"type": "library",
					"hashes": [{
						"algorithm": "SHA-256",
						"value": ""
					}]
				}]
			}`,
			wantError: false,
			expected: []Component{{
				Name:    "mylib",
				Version: "1.0.0",
				Type:    "library",
				Hashes:  []Hash{{Algorithm: "SHA-256", Value: ""}},
			}},
		},
		{
			name: "hash with file and path",
			jsonContent: `{
				"schema": "interlynk/component-manifest/v1",
				"components": [{
					"name": "mylib",
					"version": "1.0.0",
					"type": "library",
					"hashes": [{
						"algorithm": "SHA-256",
						"value": "abc123",
						"file": "mylib.tar.gz",
						"path": "/downloads/mylib-1.0.0.tar.gz"
					}]
				}]
			}`,
			wantError: false,
			expected: []Component{{
				Name:    "mylib",
				Version: "1.0.0",
				Type:    "library",
				Hashes:  []Hash{{Algorithm: "SHA-256", Value: "abc123", File: "mylib.tar.gz", Path: "/downloads/mylib-1.0.0.tar.gz"}},
			}},
		},

		// ============ EXTERNAL REFERENCES TESTS ============
		{
			name: "valid external references",
			jsonContent: `{
				"schema": "interlynk/component-manifest/v1",
				"components": [{
					"name": "mylib",
					"version": "1.0.0",
					"type": "library",
					"external_references": [
						{"type": "website", "url": "https://example.com", "comment": "Homepage"},
						{"type": "vcs", "url": "https://github.com/example/mylib", "comment": "Source"},
						{"type": "issue-tracker", "url": "https://github.com/example/mylib/issues"}
					]
				}]
			}`,
			wantError: false,
			expected: []Component{{
				Name:    "mylib",
				Version: "1.0.0",
				Type:    "library",
				ExternalRefs: []ExternalRef{
					{Type: "website", URL: "https://example.com", Comment: "Homepage"},
					{Type: "vcs", URL: "https://github.com/example/mylib", Comment: "Source"},
					{Type: "issue-tracker", URL: "https://github.com/example/mylib/issues"},
				},
			}},
		},
		{
			name: "external references - sanitized",
			jsonContent: `{
				"schema": "interlynk/component-manifest/v1",
				"components": [{
					"name": "mylib",
					"version": "1.0.0",
					"type": "library",
					"external_references": [
						{"type": "  website  ", "url": "  https://example.com  ", "comment": "  Homepage  "}
					]
				}]
			}`,
			wantError: false,
			expected: []Component{{
				Name:    "mylib",
				Version: "1.0.0",
				Type:    "library",
				ExternalRefs: []ExternalRef{
					{Type: "website", URL: "https://example.com", Comment: "Homepage"},
				},
			}},
		},

		// ============ SCOPE FIELD TESTS ============
		{
			name: "scope - required",
			jsonContent: `{
				"schema": "interlynk/component-manifest/v1",
				"components": [{
					"name": "mylib",
					"version": "1.0.0",
					"type": "library",
					"scope": "required"
				}]
			}`,
			wantError: false,
			expected: []Component{{
				Name:    "mylib",
				Version: "1.0.0",
				Type:    "library",
				Scope:   "required",
			}},
		},
		{
			name: "scope - optional",
			jsonContent: `{
				"schema": "interlynk/component-manifest/v1",
				"components": [{
					"name": "mylib",
					"version": "1.0.0",
					"type": "library",
					"scope": "optional"
				}]
			}`,
			wantError: false,
			expected: []Component{{
				Name:    "mylib",
				Version: "1.0.0",
				Type:    "library",
				Scope:   "optional",
			}},
		},
		{
			name: "scope - excluded",
			jsonContent: `{
				"schema": "interlynk/component-manifest/v1",
				"components": [{
					"name": "mylib",
					"version": "1.0.0",
					"type": "library",
					"scope": "excluded"
				}]
			}`,
			wantError: false,
			expected: []Component{{
				Name:    "mylib",
				Version: "1.0.0",
				Type:    "library",
				Scope:   "excluded",
			}},
		},
		{
			name: "scope - sanitized",
			jsonContent: `{
				"schema": "interlynk/component-manifest/v1",
				"components": [{
					"name": "mylib",
					"version": "1.0.0",
					"type": "library",
					"scope": "  required  "
				}]
			}`,
			wantError: false,
			expected: []Component{{
				Name:    "mylib",
				Version: "1.0.0",
				Type:    "library",
				Scope:   "required",
			}},
		},

		// ============ DEPENDENCIES TESTS ============
		{
			name: "depends-on as string array",
			jsonContent: `{
				"schema": "interlynk/component-manifest/v1",
				"components": [{
					"name": "mylib",
					"version": "1.0.0",
					"type": "library",
					"depends-on": ["dep1@1.0.0", "dep2@2.0.0", "dep3@3.0.0"]
				}]
			}`,
			wantError: false,
			expected: []Component{{
				Name:      "mylib",
				Version:   "1.0.0",
				Type:      "library",
				DependsOn: []string{"dep1@1.0.0", "dep2@2.0.0", "dep3@3.0.0"},
			}},
		},
		{
			name: "empty depends-on array",
			jsonContent: `{
				"schema": "interlynk/component-manifest/v1",
				"components": [{
					"name": "mylib",
					"version": "1.0.0",
					"type": "library",
					"depends-on": []
				}]
			}`,
			wantError: false,
			expected: []Component{{
				Name:    "mylib",
				Version: "1.0.0",
				Type:    "library",
			}},
		},
		{
			name: "null depends-on",
			jsonContent: `{
				"schema": "interlynk/component-manifest/v1",
				"components": [{
					"name": "mylib",
					"version": "1.0.0",
					"type": "library",
					"depends-on": null
				}]
			}`,
			wantError: false,
			expected: []Component{{
				Name:    "mylib",
				Version: "1.0.0",
				Type:    "library",
			}},
		},

		// ============ MULTIPLE COMPONENTS TESTS ============
		{
			name: "multiple valid components",
			jsonContent: `{
				"schema": "interlynk/component-manifest/v1",
				"components": [
					{
						"name": "lib1",
						"version": "1.0.0",
						"type": "library"
					},
					{
						"name": "lib2",
						"version": "2.0.0",
						"type": "library",
						"depends-on": ["lib1@1.0.0"]
					},
					{
						"name": "app1",
						"version": "3.0.0",
						"type": "application",
						"depends-on": ["lib1@1.0.0", "lib2@2.0.0"]
					}
				]
			}`,
			wantError: false,
			expected: []Component{
				{Name: "lib1", Version: "1.0.0", Type: "library"},
				{Name: "lib2", Version: "2.0.0", Type: "library", DependsOn: []string{"lib1@1.0.0"}},
				{Name: "app1", Version: "3.0.0", Type: "application", DependsOn: []string{"lib1@1.0.0", "lib2@2.0.0"}},
			},
		},
		{
			name: "multiple components - second one invalid",
			jsonContent: `{
				"schema": "interlynk/component-manifest/v1",
				"components": [
					{
						"name": "lib1",
						"version": "1.0.0",
						"type": "library"
					},
					{
						"name": "",
						"version": "2.0.0",
						"type": "library"
					}
				]
			}`,
			wantError:     true,
			errorContains: "name is required",
		},

		// ============ FILE ERROR TESTS ============
		// Note: These are tested via ParseComponentFiles which wraps parseComponents

		// ============ JSON SYNTAX ERROR TESTS ============
		{
			name: "invalid JSON syntax",
			jsonContent: `{
				"schema": "interlynk/component-manifest/v1",
				"components": [{
					"name": "mylib",
					"version": "1.0.0",
					"type": "library",
					"license": {"id": "MIT"
				}]
			}`,
			wantError:     true,
			errorContains: "invalid character",
		},
		{
			name: "missing schema field",
			jsonContent: `{
				"components": [{
					"name": "mylib",
					"version": "1.0.0",
					"type": "library"
				}]
			}`,
			wantError: false, // Schema is not validated during parse
			expected:  []Component{{Name: "mylib", Version: "1.0.0", Type: "library"}},
		},
		{
			name: "empty components array",
			jsonContent: `{
				"schema": "interlynk/component-manifest/v1",
				"components": []
			}`,
			wantError: false,
			expected:  []Component{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpFile, err := createTempJSON(tt.jsonContent)
			if err != nil {
				t.Fatalf("Failed to create temp file: %v", err)
			}
			defer os.Remove(tmpFile)

			components, err := parseJSONComponents(tmpFile)

			if tt.wantError {
				if err == nil {
					t.Errorf("parseJSONComponents() expected error containing %q, got nil", tt.errorContains)
					return
				}
				if !strings.Contains(err.Error(), tt.errorContains) {
					t.Errorf("parseJSONComponents() error = %v, want error containing %q", err, tt.errorContains)
				}
				return
			}

			if err != nil {
				t.Errorf("parseJSONComponents() unexpected error = %v", err)
				return
			}

			if tt.expected != nil {
				compareComponents(t, components, tt.expected)
			}
		})
	}
}

// createTempJSON creates a temporary JSON file with the given content
func createTempJSON(content string) (string, error) {
	tmpFile, err := os.CreateTemp("", "components-*.json")
	if err != nil {
		return "", err
	}
	defer tmpFile.Close()

	if _, err := tmpFile.WriteString(content); err != nil {
		os.Remove(tmpFile.Name())
		return "", err
	}

	return tmpFile.Name(), nil
}

// compareComponents compares the actual components with expected values
func compareComponents(t *testing.T, actual, expected []Component) {
	t.Helper()

	if len(actual) != len(expected) {
		t.Errorf("len(components) = %d, want %d", len(actual), len(expected))
		return
	}

	for i := range expected {
		comp := actual[i]
		exp := expected[i]

		if comp.Name != exp.Name {
			t.Errorf("[%d] Name = %q, want %q", i, comp.Name, exp.Name)
		}
		if comp.Version != exp.Version {
			t.Errorf("[%d] Version = %q, want %q", i, comp.Version, exp.Version)
		}
		if comp.Type != exp.Type {
			t.Errorf("[%d] Type = %q, want %q", i, comp.Type, exp.Type)
		}
		if comp.Description != exp.Description {
			t.Errorf("[%d] Description = %q, want %q", i, comp.Description, exp.Description)
		}
		if comp.PURL != exp.PURL {
			t.Errorf("[%d] PURL = %q, want %q", i, comp.PURL, exp.PURL)
		}
		if comp.CPE != exp.CPE {
			t.Errorf("[%d] CPE = %q, want %q", i, comp.CPE, exp.CPE)
		}
		if comp.Scope != exp.Scope {
			t.Errorf("[%d] Scope = %q, want %q", i, comp.Scope, exp.Scope)
		}

		// Compare Supplier
		if comp.Supplier.Name != exp.Supplier.Name {
			t.Errorf("[%d] Supplier.Name = %q, want %q", i, comp.Supplier.Name, exp.Supplier.Name)
		}
		if comp.Supplier.Email != exp.Supplier.Email {
			t.Errorf("[%d] Supplier.Email = %q, want %q", i, comp.Supplier.Email, exp.Supplier.Email)
		}
		if comp.Supplier.URL != exp.Supplier.URL {
			t.Errorf("[%d] Supplier.URL = %q, want %q", i, comp.Supplier.URL, exp.Supplier.URL)
		}

		// Compare License
		if comp.License.Expression != exp.License.Expression {
			t.Errorf("[%d] License.Expression = %q, want %q", i, comp.License.Expression, exp.License.Expression)
		}
		if comp.License.ID != exp.License.ID {
			t.Errorf("[%d] License.ID = %q, want %q", i, comp.License.ID, exp.License.ID)
		}
		if comp.License.Text != exp.License.Text {
			t.Errorf("[%d] License.Text = %q, want %q", i, comp.License.Text, exp.License.Text)
		}
		if comp.License.File != exp.License.File {
			t.Errorf("[%d] License.File = %q, want %q", i, comp.License.File, exp.License.File)
		}

		// Compare Tags
		if len(comp.Tags) != len(exp.Tags) {
			t.Errorf("[%d] len(Tags) = %d, want %d", i, len(comp.Tags), len(exp.Tags))
		} else {
			for j := range exp.Tags {
				if comp.Tags[j] != exp.Tags[j] {
					t.Errorf("[%d] Tags[%d] = %q, want %q", i, j, comp.Tags[j], exp.Tags[j])
				}
			}
		}

		// Compare DependsOn
		if len(comp.DependsOn) != len(exp.DependsOn) {
			t.Errorf("[%d] len(DependsOn) = %d, want %d", i, len(comp.DependsOn), len(exp.DependsOn))
		} else {
			for j := range exp.DependsOn {
				if comp.DependsOn[j] != exp.DependsOn[j] {
					t.Errorf("[%d] DependsOn[%d] = %q, want %q", i, j, comp.DependsOn[j], exp.DependsOn[j])
				}
			}
		}

		// Compare Hashes
		if len(comp.Hashes) != len(exp.Hashes) {
			t.Errorf("[%d] len(Hashes) = %d, want %d", i, len(comp.Hashes), len(exp.Hashes))
		} else {
			for j := range exp.Hashes {
				if comp.Hashes[j].Algorithm != exp.Hashes[j].Algorithm {
					t.Errorf("[%d] Hashes[%d].Algorithm = %q, want %q", i, j, comp.Hashes[j].Algorithm, exp.Hashes[j].Algorithm)
				}
				if comp.Hashes[j].Value != exp.Hashes[j].Value {
					t.Errorf("[%d] Hashes[%d].Value = %q, want %q", i, j, comp.Hashes[j].Value, exp.Hashes[j].Value)
				}
				if comp.Hashes[j].File != exp.Hashes[j].File {
					t.Errorf("[%d] Hashes[%d].File = %q, want %q", i, j, comp.Hashes[j].File, exp.Hashes[j].File)
				}
				if comp.Hashes[j].Path != exp.Hashes[j].Path {
					t.Errorf("[%d] Hashes[%d].Path = %q, want %q", i, j, comp.Hashes[j].Path, exp.Hashes[j].Path)
				}
			}
		}

		// Compare ExternalRefs
		if len(comp.ExternalRefs) != len(exp.ExternalRefs) {
			t.Errorf("[%d] len(ExternalRefs) = %d, want %d", i, len(comp.ExternalRefs), len(exp.ExternalRefs))
		} else {
			for j := range exp.ExternalRefs {
				if comp.ExternalRefs[j].Type != exp.ExternalRefs[j].Type {
					t.Errorf("[%d] ExternalRefs[%d].Type = %q, want %q", i, j, comp.ExternalRefs[j].Type, exp.ExternalRefs[j].Type)
				}
				if comp.ExternalRefs[j].URL != exp.ExternalRefs[j].URL {
					t.Errorf("[%d] ExternalRefs[%d].URL = %q, want %q", i, j, comp.ExternalRefs[j].URL, exp.ExternalRefs[j].URL)
				}
				if comp.ExternalRefs[j].Comment != exp.ExternalRefs[j].Comment {
					t.Errorf("[%d] ExternalRefs[%d].Comment = %q, want %q", i, j, comp.ExternalRefs[j].Comment, exp.ExternalRefs[j].Comment)
				}
			}
		}
	}
}
