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

package gcomps

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

//go:embed schemas/component-manifest-v1.schema.json
var schemaJSON []byte

// PrintSchema writes the raw JSON Schema to the provided writer.
// If w is nil, it writes to stdout.
func PrintSchema(w io.Writer) error {
	if w == nil {
		w = io.Discard
	}
	_, err := w.Write(schemaJSON)
	return err
}

// GetSchema returns the raw JSON Schema as bytes.
func GetSchema() []byte {
	return schemaJSON
}

// DescribeSchema returns a human-readable description of all fields.
func DescribeSchema() string {
	var schema map[string]interface{}

	if err := json.Unmarshal(schemaJSON, &schema); err != nil {
		return fmt.Sprintf("Error parsing schema: %v", err)
	}

	var b strings.Builder

	// Header
	b.WriteString("Component manifest (schema: interlynk/component-manifest/v1)\n")
	b.WriteString("\n")

	// Required fields section
	b.WriteString("Required:\n")
	if props, ok := schema["properties"].(map[string]interface{}); ok {
		if required, ok := schema["required"].([]interface{}); ok {
			for _, reqField := range required {
				if reqStr, ok := reqField.(string); ok {
					if prop, ok := props[reqStr].(map[string]interface{}); ok {
						describeField(&b, reqStr, prop, true)
					}
				}
			}
		}
	}

	// Component fields section
	b.WriteString("\nComponent fields:\n")

	// Field descriptions with custom formatting
	fieldDescriptions := []struct {
		name        string
		typ         string
		required    bool
		description string
	}{
		{"name", "string", true, "Component name"},
		{"version", "string", true, "Component version"},
		{"type", "string", false, "library (default) | application | framework | container | operating-system | device | firmware | file | platform | device-driver | machine-learning-model | data"},
		{"description", "string", false, "Human-readable description"},
		{"supplier", "object", false, "{ name, email, url }"},
		{"license", "string|obj", false, "\"MIT\" | { id } | { id, text } | { id, file }"},
		{"purl", "string", false, "Package URL — for patched/vendored components must differ from any pedigree.ancestors[].purl"},
		{"cpe", "string", false, "CPE identifier"},
		{"external_references", "array", false, "[{ type, url, comment? }]"},
		{"hashes", "array", false, "literal value | file | path with optional extensions filter (SHA-256, SHA-512)"},
		{"scope", "string", false, "required (default) | optional | excluded"},
		{"pedigree", "object", false, "ancestors, descendants, variants, commits, patches, notes"},
		{"depends_on", "array", false, "[\"name@version\", ...]"},
		{"tags", "array", false, "Per-build filtering via --tags / --exclude-tags"},
	}

	for _, fd := range fieldDescriptions {
		fmt.Fprintf(&b, "  %-20s %-10s %s   %s\n", fd.name, fd.typ, requiredStr(fd.required), fd.description)
	}

	b.WriteString("\n")
	b.WriteString("Run `sbomasm generate components --schema` for the full JSON Schema.\n")

	return b.String()
}

func requiredStr(required bool) string {
	if required {
		return "required"
	}
	return "optional"
}

func describeField(b *strings.Builder, name string, prop map[string]interface{}, required bool) {
	propType := ""
	if t, ok := prop["type"].(string); ok {
		propType = t
	}

	// Special handling for known fields
	var description string
	switch name {
	case "schema":
		description = `"interlynk/component-manifest/v1"`
	case "components":
		description = "List of third-party components"
	default:
		if d, ok := prop["description"].(string); ok {
			description = d
		}
	}

	fmt.Fprintf(b, "  %-20s %-10s %s\n", name, propType, description)
}
