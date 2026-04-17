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
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/interlynk-io/sbomasm/v2/pkg/logger"
)

const defaultJSONFilename = ".components.json"
const defaultCSVFilename = ".components.csv"
const schemaVersion = "interlynk/component-manifest/v1"

// Generate creates a component scaffold file based on the provided parameters.
func Generate(params *GenerateComponentsParams) error {
	log := logger.FromContext(*params.Ctx)
	log.Debugf("generating component scaffold with params: output=%s, csv=%v, force=%v", params.Output, params.CSV, params.Force)

	// Step 1: Resolve output path and format
	outputPath, isCSV, err := resolveOutputPathAndFormat(params.Output, params.CSV)
	if err != nil {
		log.Debugf("failed to resolve output path: %v", err)
		return err
	}

	log.Debugf("resolved output path: %s (csv=%v)", outputPath, isCSV)

	// Step 2: Check overwrite safety
	if _, err := os.Stat(outputPath); err == nil {
		if !params.Force {
			log.Debugf("refusing to overwrite existing file: %s", outputPath)
			return fmt.Errorf("refusing to overwrite %s (use --force to overwrite)", outputPath)
		}
		log.Debugf("overwriting existing file: %s", outputPath)
	}

	// Step 3: Validate parent directory exists
	parentDir := filepath.Dir(outputPath)
	if parentDir != "" && parentDir != "." {
		if _, err := os.Stat(parentDir); os.IsNotExist(err) {
			log.Debugf("parent directory does not exist: %s", parentDir)
			return fmt.Errorf("directory %s does not exist", parentDir)
		}
	}

	// Step 4: Generate scaffold content
	var content []byte
	if isCSV {
		log.Debugf("generating CSV scaffold")
		content, err = generateCSVScaffold()
	} else {
		log.Debugf("generating JSON scaffold")
		content, err = generateJSONScaffold()
	}

	if err != nil {
		log.Debugf("failed to generate scaffold: %v", err)
		return fmt.Errorf("failed to generate scaffold: %w", err)
	}

	// Step 5: Write file
	if err := os.WriteFile(outputPath, content, 0644); err != nil {
		log.Debugf("failed to write file: %v", err)
		return fmt.Errorf("failed to write file: %w", err)
	}

	log.Debugf("successfully wrote %s", outputPath)

	// Step 6: Print success
	fmt.Printf("wrote %s\n", outputPath)
	return nil
}

// resolveOutputPathAndFormat determines the final output path and format.
func resolveOutputPathAndFormat(output string, csvFlag bool) (string, bool, error) {
	// Check --output flag
	if output != "" {
		// Check if it's a directory
		info, err := os.Stat(output)
		if err == nil && info.IsDir() {
			isCSV := csvFlag || hasCSVExtension("")

			filename := defaultJSONFilename
			if isCSV {
				filename = defaultCSVFilename
			}
			return filepath.Join(output, filename), isCSV, nil
		}

		// It's a file path, determine format from extension or flag
		isCSV := csvFlag || hasCSVExtension(output)
		return output, isCSV, nil
	}

	// Priority 2: default to current directory
	isCSV := csvFlag
	filename := defaultJSONFilename
	if isCSV {
		filename = defaultCSVFilename
	}
	return filename, isCSV, nil
}

// hasCSVExtension checks if the path has a .csv extension.
func hasCSVExtension(path string) bool {
	return strings.HasSuffix(strings.ToLower(path), ".csv")
}

// generateJSONScaffold creates the JSON scaffold content.
func generateJSONScaffold() ([]byte, error) {
	manifest := Manifest{
		Schema: schemaVersion,
		Components: []Component{
			{
				Name:        "libexample",
				Version:     "1.0.0",
				Type:        "library",
				Description: "Example component replace with a real entry or delete",
				Supplier: &Supplier{
					Name:  "Example Org",
					Email: "security@example.com",
				},
				License: "MIT",
				PURL:    "pkg:generic/example/libexample@1.0.0",
				ExternalRefs: []ExternalRef{
					{Type: "website", URL: "https://example.com/libexample"},
					{Type: "vcs", URL: "https://github.com/example/libexample"},
				},
				Hashes: []Hash{
					{
						Algorithm: "SHA-256",
						Value:     "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
					},
				},
				Scope: "required",
				Tags:  []string{"core"},
			},
		},
	}

	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(manifest); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// generateCSVScaffold creates the CSV scaffold content.
func generateCSVScaffold() ([]byte, error) {
	var buf bytes.Buffer

	// Write header comment with schema version
	buf.WriteString("#")
	buf.WriteString(schemaVersion)
	buf.WriteString("\n")

	// Write header row
	headers := []string{
		"name", "version", "type", "description",
		"supplier_name", "supplier_email", "supplier_url",
		"license", "purl", "cpe",
		"external_refs",
		"hashes",
		"scope", "depends_on", "tags",
	}

	// Create CSV writer
	writer := csv.NewWriter(&buf)
	if err := writer.Write(headers); err != nil {
		return nil, err
	}

	// Write example row
	exampleRow := []string{
		"libexample",
		"1.0.0",
		"library",
		"Example component replace with a real entry or delete",
		"Example Org",
		"security@example.com",
		"",
		"MIT",
		"pkg:generic/example/libexample@1.0.0",
		"",
		"website:https://example.com/libexample,vcs:https://github.com/example/libexample",
		"SHA-256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		"required",
		"",
		"core",
	}
	if err := writer.Write(exampleRow); err != nil {
		return nil, err
	}

	writer.Flush()
	if err := writer.Error(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// WriteSchema writes the JSON Schema to the provided writer or file.
// If output is "-", writes to stdout. Otherwise writes to the file path.
func WriteSchema(ctx context.Context, output string, force bool) error {
	log := logger.FromContext(ctx)
	log.Debugf("writing schema to: %s", output)

	if output == "" || output == "-" {
		log.Debugf("writing schema to stdout")
		_, err := os.Stdout.Write(GetSchema())
		return err
	}

	if _, err := os.Stat(output); err == nil {
		if !force {
			log.Debugf("refusing to overwrite existing file: %s", output)
			return fmt.Errorf("refusing to overwrite %s (use --force to overwrite)", output)
		}
		log.Debugf("overwriting existing schema file: %s", output)
	}

	if err := os.WriteFile(output, schemaJSON, 0644); err != nil {
		log.Debugf("failed to write schema: %v", err)
		return fmt.Errorf("failed to write schema: %w", err)
	}

	log.Debugf("successfully wrote schema to %s", output)
	fmt.Printf("wrote %s\n", output)
	return nil
}
