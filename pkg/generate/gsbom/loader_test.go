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
	"path/filepath"
	"strings"
	"testing"
)

// Common YAML templates used across tests
var (
	validMinimalArtifact = `
app:
  name: myapp
  version: 1.0.0
  primary_purpose: application
`
	validMinimalExpected = &Artifact{
		Name:           "myapp",
		Version:        "1.0.0",
		PrimaryPurpose: "application",
		Lifecycles:     []Lifecycle{{Phase: "build"}},
	}

	// Helper to build YAML with custom primary_purpose
	yamlWithPurpose = func(purpose string) string {
		return `
app:
  name: myapp
  version: 1.0.0
  primary_purpose: ` + purpose + `
`
	}

	// Helper to build expected artifact with custom primary_purpose
	expectedWithPurpose = func(purpose string) *Artifact {
		return &Artifact{
			Name:           "myapp",
			Version:        "1.0.0",
			PrimaryPurpose: purpose,
			Lifecycles:     []Lifecycle{{Phase: "build"}},
		}
	}
)

func TestLoadArtifactConfig(t *testing.T) {
	tests := []struct {
		name          string
		yamlContent   string
		wantError     bool
		errorContains string
		expected      *Artifact
	}{
		// ============ REQUIRED FIELDS TESTS ============
		{
			name:        "valid minimal artifact",
			yamlContent: validMinimalArtifact,
			wantError:   false,
			expected:    validMinimalExpected,
		},
		{
			name: "missing name field",
			yamlContent: `
app:
  version: 1.0.0
  primary_purpose: application
`,
			wantError:     true,
			errorContains: "artifact name is required",
		},
		{
			name: "missing version field",
			yamlContent: `
app:
  name: myapp
  primary_purpose: application
`,
			wantError:     true,
			errorContains: "artifact version is required",
		},
		{
			name: "missing primary_purpose field",
			yamlContent: `
app:
  name: myapp
  version: 1.0.0
`,
			wantError:     true,
			errorContains: "artifact primary_purpose is required",
		},
		{
			name: "whitespace-only name",
			yamlContent: `
app:
  name: "   "
  version: 1.0.0
  primary_purpose: application
`,
			wantError:     true,
			errorContains: "artifact name is required",
		},
		{
			name: "placeholder [REQUIRED] in name",
			yamlContent: `
app:
  name: "[REQUIRED]"
  version: 1.0.0
  primary_purpose: application
`,
			wantError:     true,
			errorContains: "artifact name is required",
		},
		{
			name: "placeholder [REQUIRED] in version",
			yamlContent: `
app:
  name: myapp
  version: "[REQUIRED]"
  primary_purpose: application
`,
			wantError:     true,
			errorContains: "artifact version is required",
		},
		{
			name: "placeholder [REQUIRED] in primary_purpose",
			yamlContent: `
app:
  name: myapp
  version: 1.0.0
  primary_purpose: "[REQUIRED]"
`,
			wantError:     true,
			errorContains: "artifact primary_purpose is required",
		},

		// ============ PRIMARY PURPOSE VALIDATION ============
		{
			name:        "valid primary_purpose - library",
			yamlContent: yamlWithPurpose("library"),
			wantError:   false,
			expected:    expectedWithPurpose("library"),
		},
		{
			name:        "valid primary_purpose - framework",
			yamlContent: yamlWithPurpose("framework"),
			wantError:   false,
			expected:    expectedWithPurpose("framework"),
		},
		{
			name:        "valid primary_purpose - container",
			yamlContent: yamlWithPurpose("container"),
			wantError:   false,
			expected:    expectedWithPurpose("container"),
		},
		{
			name:        "valid primary_purpose - operating-system",
			yamlContent: yamlWithPurpose("operating-system"),
			wantError:   false,
			expected:    expectedWithPurpose("operating-system"),
		},
		{
			name: "invalid primary_purpose value",
			yamlContent: `
app:
  name: myapp
  version: 1.0.0
  primary_purpose: invalid-type
`,
			wantError:     true,
			errorContains: "invalid primary_purpose",
		},
		{
			name:        "case-insensitive primary_purpose - LIBRARY accepted",
			yamlContent: yamlWithPurpose("LIBRARY"),
			wantError:   false,
			expected:    expectedWithPurpose("library"), // gets lowercased during validation
		},
		{
			name:        "case-insensitive primary_purpose - Application accepted",
			yamlContent: yamlWithPurpose("Application"),
			wantError:   false,
			expected:    expectedWithPurpose("application"), // gets lowercased during validation
		},

		// ============ SANITIZATION TESTS ============
		{
			name: "sanitized fields with whitespace",
			yamlContent: `
app:
  name: "  myapp  "
  version: "  1.0.0  "
  primary_purpose: "  application  "
  description: "  My App Description  "
`,
			wantError: false,
			expected: &Artifact{
				Name:           "myapp",
				Version:        "1.0.0",
				PrimaryPurpose: "application",
				Description:    "My App Description",
				Lifecycles:     []Lifecycle{{Phase: "build"}},
			},
		},
		{
			name:        "placeholder [OPTIONAL] becomes empty",
			yamlContent: validMinimalArtifact + `  description: "[OPTIONAL]"
`,
			wantError:   false,
			expected: &Artifact{
				Name:           "myapp",
				Version:        "1.0.0",
				PrimaryPurpose: "application",
				Description:    "",
				Lifecycles:     []Lifecycle{{Phase: "build"}},
			},
		},
		{
			name:        "case-insensitive placeholder [optional]",
			yamlContent: validMinimalArtifact + `  description: "[optional]"
`,
			wantError:   false,
			expected: &Artifact{
				Name:           "myapp",
				Version:        "1.0.0",
				PrimaryPurpose: "application",
				Description:    "",
				Lifecycles:     []Lifecycle{{Phase: "build"}},
			},
		},

		// ============ LIFECYCLE TESTS ============
		{
			name:        "valid lifecycle - design",
			yamlContent: validMinimalArtifact + `  lifecycles:
    - phase: design
`,
			wantError: false,
			expected: &Artifact{
				Name:           "myapp",
				Version:        "1.0.0",
				PrimaryPurpose: "application",
				Lifecycles:     []Lifecycle{{Phase: "design"}},
			},
		},
		{
			name:        "valid lifecycle - build (default)",
			yamlContent: validMinimalArtifact,
			wantError:   false,
			expected:    validMinimalExpected,
		},
		{
			name:        "valid multiple lifecycles",
			yamlContent: validMinimalArtifact + `  lifecycles:
    - phase: design
    - phase: pre-build
    - phase: build
`,
			wantError: false,
			expected: &Artifact{
				Name:           "myapp",
				Version:        "1.0.0",
				PrimaryPurpose: "application",
				Lifecycles: []Lifecycle{
					{Phase: "design"},
					{Phase: "pre-build"},
					{Phase: "build"},
				},
			},
		},
		{
			name: "invalid lifecycle phase",
			yamlContent: validMinimalArtifact + `  lifecycles:
    - phase: invalid-phase
`,
			wantError:     true,
			errorContains: "invalid lifecycle phase",
		},
		{
			name:        "empty lifecycles array gets default",
			yamlContent: validMinimalArtifact + `  lifecycles: []
`,
			wantError:   false,
			expected:    validMinimalExpected,
		},

		// ============ OPTIONAL FIELDS TESTS ============
		{
			name: "all optional fields present",
			yamlContent: `
app:
  name: myapp
  version: 1.0.0
  primary_purpose: application
  description: My application description
  supplier:
    name: Acme Corp
    email: security@acme.example
    url: https://acme.example
  author:
    - name: John Doe
      email: john@example.com
  license:
    id: MIT
  purl: pkg:generic/acme/myapp@1.0.0
  cpe: cpe:2.3:a:acme:myapp:1.0.0
  copyright: "Copyright 2026 Acme Corp"
  external_refs:
    - type: website
      url: https://myapp.example
      comment: Project website
  lifecycles:
    - phase: build
output:
  spec: cyclonedx
  spec_version: "1.6"
  file_format: json
`,
			wantError: false,
			expected: &Artifact{
				Name:           "myapp",
				Version:        "1.0.0",
				PrimaryPurpose: "application",
				Description:    "My application description",
				Supplier: Supplier{
					Name:  "Acme Corp",
					Email: "security@acme.example",
					URL:   "https://acme.example",
				},
				Authors: []Author{
					{Name: "John Doe", Email: "john@example.com"},
				},
				License:        "MIT",
				PURL:           "pkg:generic/acme/myapp@1.0.0",
				CPE:            "cpe:2.3:a:acme:myapp:1.0.0",
				Copyright:      "Copyright 2026 Acme Corp",
				ExternalRefs: []ExternalRef{
					{Type: "website", URL: "https://myapp.example", Comment: "Project website"},
				},
				Lifecycles: []Lifecycle{{Phase: "build"}},
				OutputConfig: OutputConfig{
					Spec:        "cyclonedx",
					SpecVersion: "1.6",
					FileFormat:  "json",
				},
			},
		},
		{
			name: "sanitized supplier fields",
			yamlContent: `
app:
  name: myapp
  version: 1.0.0
  primary_purpose: application
  supplier:
    name: "  Acme Corp  "
    email: "  security@acme.example  "
    url: "  https://acme.example  "
`,
			wantError: false,
			expected: &Artifact{
				Name:           "myapp",
				Version:        "1.0.0",
				PrimaryPurpose: "application",
				Supplier: Supplier{
					Name:  "Acme Corp",
					Email: "security@acme.example",
					URL:   "https://acme.example",
				},
				Lifecycles: []Lifecycle{{Phase: "build"}},
			},
		},
		{
			name: "sanitized author fields",
			yamlContent: `
app:
  name: myapp
  version: 1.0.0
  primary_purpose: application
  author:
    - name: "  John Doe  "
      email: "  john@example.com  "
`,
			wantError: false,
			expected: &Artifact{
				Name:           "myapp",
				Version:        "1.0.0",
				PrimaryPurpose: "application",
				Authors: []Author{
					{Name: "John Doe", Email: "john@example.com"},
				},
				Lifecycles: []Lifecycle{{Phase: "build"}},
			},
		},
		{
			name: "sanitized external_refs fields",
			yamlContent: `
app:
  name: myapp
  version: 1.0.0
  primary_purpose: application
  external_refs:
    - type: "  website  "
      url: "  https://example.com  "
      comment: "  My comment  "
`,
			wantError: false,
			expected: &Artifact{
				Name:           "myapp",
				Version:        "1.0.0",
				PrimaryPurpose: "application",
				ExternalRefs: []ExternalRef{
					{Type: "website", URL: "https://example.com", Comment: "My comment"},
				},
				Lifecycles: []Lifecycle{{Phase: "build"}},
			},
		},
		{
			name: "empty optional fields are preserved as empty",
			yamlContent: `
app:
  name: myapp
  version: 1.0.0
  primary_purpose: application
  description: ""
  supplier:
    name: ""
`,
			wantError: false,
			expected: &Artifact{
				Name:           "myapp",
				Version:        "1.0.0",
				PrimaryPurpose: "application",
				Description:    "",
				Supplier:       Supplier{Name: ""},
				Lifecycles:     []Lifecycle{{Phase: "build"}},
			},
		},

		// ============ FILE ERROR TESTS ============
		{
			name:          "file not found",
			yamlContent:   "",
			wantError:     true,
			errorContains: "artifact metadata file not found",
		},
		{
			name: "invalid yaml syntax",
			yamlContent: `
app:
  name: myapp
  version: 1.0.0
  primary_purpose: application
  invalid: [
    unclosed bracket
`,
			wantError:     true,
			errorContains: "failed to parse yaml",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temp file for tests that need file content
			var tmpFile string
			var err error

			if tt.yamlContent != "" {
				tmpFile, err = createTempYAML(tt.yamlContent)
				if err != nil {
					t.Fatalf("Failed to create temp file: %v", err)
				}
				defer os.Remove(tmpFile)
			} else {
				// For "file not found" test, use a non-existent file
				tmpFile = filepath.Join(t.TempDir(), "nonexistent.yaml")
			}

			artifact, err := LoadArtifactConfig(tmpFile)

			if tt.wantError {
				if err == nil {
					t.Errorf("LoadArtifactConfig() expected error containing %q, got nil", tt.errorContains)
					return
				}
				if !strings.Contains(err.Error(), tt.errorContains) {
					t.Errorf("LoadArtifactConfig() error = %v, want error containing %q", err, tt.errorContains)
					return
				}
				return
			}

			if err != nil {
				t.Errorf("LoadArtifactConfig() unexpected error = %v", err)
				return
			}

			if tt.expected != nil {
				compareArtifacts(t, artifact, tt.expected)
			}
		})
	}
}

// createTempYAML creates a temporary YAML file with the given content
func createTempYAML(content string) (string, error) {
	tmpFile, err := os.CreateTemp("", "artifact-*.yaml")
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

// compareArtifacts compares the actual artifact with expected values
func compareArtifacts(t *testing.T, actual, expected *Artifact) {
	t.Helper()

	if actual.Name != expected.Name {
		t.Errorf("Name = %q, want %q", actual.Name, expected.Name)
	}
	if actual.Version != expected.Version {
		t.Errorf("Version = %q, want %q", actual.Version, expected.Version)
	}
	if actual.PrimaryPurpose != expected.PrimaryPurpose {
		t.Errorf("PrimaryPurpose = %q, want %q", actual.PrimaryPurpose, expected.PrimaryPurpose)
	}
	if actual.Description != expected.Description {
		t.Errorf("Description = %q, want %q", actual.Description, expected.Description)
	}
	if actual.License != expected.License {
		t.Errorf("License = %q, want %q", actual.License, expected.License)
	}
	if actual.PURL != expected.PURL {
		t.Errorf("PURL = %q, want %q", actual.PURL, expected.PURL)
	}
	if actual.CPE != expected.CPE {
		t.Errorf("CPE = %q, want %q", actual.CPE, expected.CPE)
	}
	if actual.Copyright != expected.Copyright {
		t.Errorf("Copyright = %q, want %q", actual.Copyright, expected.Copyright)
	}

	// Compare Supplier
	if actual.Supplier.Name != expected.Supplier.Name {
		t.Errorf("Supplier.Name = %q, want %q", actual.Supplier.Name, expected.Supplier.Name)
	}
	if actual.Supplier.Email != expected.Supplier.Email {
		t.Errorf("Supplier.Email = %q, want %q", actual.Supplier.Email, expected.Supplier.Email)
	}
	if actual.Supplier.URL != expected.Supplier.URL {
		t.Errorf("Supplier.URL = %q, want %q", actual.Supplier.URL, expected.Supplier.URL)
	}

	// Compare Authors
	if len(actual.Authors) != len(expected.Authors) {
		t.Errorf("len(Authors) = %d, want %d", len(actual.Authors), len(expected.Authors))
	} else {
		for i := range expected.Authors {
			if actual.Authors[i].Name != expected.Authors[i].Name {
				t.Errorf("Authors[%d].Name = %q, want %q", i, actual.Authors[i].Name, expected.Authors[i].Name)
			}
			if actual.Authors[i].Email != expected.Authors[i].Email {
				t.Errorf("Authors[%d].Email = %q, want %q", i, actual.Authors[i].Email, expected.Authors[i].Email)
			}
		}
	}

	// Compare Lifecycles
	if len(actual.Lifecycles) != len(expected.Lifecycles) {
		t.Errorf("len(Lifecycles) = %d, want %d", len(actual.Lifecycles), len(expected.Lifecycles))
	} else {
		for i := range expected.Lifecycles {
			if actual.Lifecycles[i].Phase != expected.Lifecycles[i].Phase {
				t.Errorf("Lifecycles[%d].Phase = %q, want %q", i, actual.Lifecycles[i].Phase, expected.Lifecycles[i].Phase)
			}
		}
	}

	// Compare ExternalRefs
	if len(actual.ExternalRefs) != len(expected.ExternalRefs) {
		t.Errorf("len(ExternalRefs) = %d, want %d", len(actual.ExternalRefs), len(expected.ExternalRefs))
	} else {
		for i := range expected.ExternalRefs {
			if actual.ExternalRefs[i].Type != expected.ExternalRefs[i].Type {
				t.Errorf("ExternalRefs[%d].Type = %q, want %q", i, actual.ExternalRefs[i].Type, expected.ExternalRefs[i].Type)
			}
			if actual.ExternalRefs[i].URL != expected.ExternalRefs[i].URL {
				t.Errorf("ExternalRefs[%d].URL = %q, want %q", i, actual.ExternalRefs[i].URL, expected.ExternalRefs[i].URL)
			}
			if actual.ExternalRefs[i].Comment != expected.ExternalRefs[i].Comment {
				t.Errorf("ExternalRefs[%d].Comment = %q, want %q", i, actual.ExternalRefs[i].Comment, expected.ExternalRefs[i].Comment)
			}
		}
	}

	// Compare OutputConfig
	if actual.OutputConfig.Spec != expected.OutputConfig.Spec {
		t.Errorf("OutputConfig.Spec = %q, want %q", actual.OutputConfig.Spec, expected.OutputConfig.Spec)
	}
	if actual.OutputConfig.SpecVersion != expected.OutputConfig.SpecVersion {
		t.Errorf("OutputConfig.SpecVersion = %q, want %q", actual.OutputConfig.SpecVersion, expected.OutputConfig.SpecVersion)
	}
	if actual.OutputConfig.FileFormat != expected.OutputConfig.FileFormat {
		t.Errorf("OutputConfig.FileFormat = %q, want %q", actual.OutputConfig.FileFormat, expected.OutputConfig.FileFormat)
	}
}
