// Copyright 2026 Interlynk.io
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package gsbom

import (
	"embed"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

//go:embed schemas/component-manifest-v1.schema.json
var schemaFS embed.FS

var (
	// compiledSchema is cached after first compilation
	compiledSchema *jsonschema.Schema
	schemaErr      error
)

// ValidateJSONSchema validates a JSON file against the component manifest schema.
// Returns nil if valid, error with validation details if invalid.
func ValidateJSONSchema(filePath string) error {
	// Load and compile schema if not already done
	if compiledSchema == nil && schemaErr == nil {
		compiledSchema, schemaErr = compileSchema()
	}
	if schemaErr != nil {
		return fmt.Errorf("failed to compile schema: %w", schemaErr)
	}

	// Read and parse the JSON file
	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	// Parse JSON into interface{} for validation
	var doc interface{}
	if err := json.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("failed to parse JSON: %w", err)
	}

	// Validate against schema
	if err := compiledSchema.Validate(doc); err != nil {
		return formatValidationError(err, filePath)
	}

	return nil
}

// compileSchema loads and compiles the JSON schema from embedded FS.
func compileSchema() (*jsonschema.Schema, error) {
	compiler := jsonschema.NewCompiler()

	// Read schema from embedded file
	schemaData, err := schemaFS.ReadFile("schemas/component-manifest-v1.schema.json")
	if err != nil {
		return nil, fmt.Errorf("failed to read embedded schema: %w", err)
	}

	// Parse schema
	var schemaDoc interface{}
	if err := json.Unmarshal(schemaData, &schemaDoc); err != nil {
		return nil, fmt.Errorf("failed to parse schema: %w", err)
	}

	// Compile schema
	if err := compiler.AddResource("https://interlynk.io/schemas/component-manifest-v1.schema.json", schemaDoc); err != nil {
		return nil, fmt.Errorf("failed to add schema to compiler: %w", err)
	}

	compiled, err := compiler.Compile("https://interlynk.io/schemas/component-manifest-v1.schema.json")
	if err != nil {
		return nil, fmt.Errorf("failed to compile schema: %w", err)
	}

	return compiled, nil
}

// formatValidationError formats the jsonschema validation error into a readable message.
func formatValidationError(err error, filePath string) error {
	if validationErr, ok := err.(*jsonschema.ValidationError); ok {
		// Use DetailedOutput to get structured error information
		detailed := validationErr.DetailedOutput()
		if detailed.Error != nil {
			return fmt.Errorf("JSON schema validation failed for %s: %s", filePath, detailed.Error)
		}
		if len(detailed.Errors) > 0 {
			return fmt.Errorf("JSON schema validation failed for %s:\n%s", filePath, formatOutputUnitErrors(detailed.Errors, 0))
		}
		return fmt.Errorf("JSON schema validation failed for %s", filePath)
	}
	return fmt.Errorf("JSON schema validation failed for %s: %v", filePath, err)
}

// formatOutputUnitErrors recursively formats validation errors.
func formatOutputUnitErrors(errors []jsonschema.OutputUnit, indent int) string {
	if len(errors) == 0 {
		return ""
	}

	var messages []string
	prefix := strings.Repeat("  ", indent)

	for _, err := range errors {
		location := err.InstanceLocation
		if location == "" {
			location = "root"
		}

		// Format the error message
		if err.Error != nil {
			msg := fmt.Sprintf("%s- %s: %s", prefix, location, err.Error)
			messages = append(messages, msg)
		}

		// Add nested errors
		if len(err.Errors) > 0 {
			nested := formatOutputUnitErrors(err.Errors, indent+1)
			if nested != "" {
				messages = append(messages, nested)
			}
		}
	}

	return strings.Join(messages, "\n")
}
