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
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Schema validation errors
var (
	ErrMissingSchema = errors.New("missing schema marker")
	ErrInvalidSchema = errors.New("invalid schema")
)

// CollectInputFiles performs the following steps:
// - Appends any explicitly provided input files to the explicit list.
// - If a RecursePath is provided, it walks through the directory tree starting from that path.
//   - For each file encountered, it checks if the filename matches the specified Filename (e.g., ".components.json").
//   - If a match is found, the file path is added to the discovered list.
//
// - Finally, it returns the explicit files, discovered files, and any warnings.
// Files without a schema marker are handled differently:
//   - Explicit files: missing schema = error
//   - Discovered files: missing schema = silently skipped
func CollectInputFiles(params *GenerateSBOMParams) ([]string, []string, []error) {
	var explicitFiles []string
	var discoveredFiles []string
	var errors []error
	seen := make(map[string]bool) // Track unique file paths

	// Helper to add file only if not already seen
	addFile := func(path string, isDiscovered bool) {
		// Use Clean to normalize paths for comparison
		cleanPath := filepath.Clean(path)
		if !seen[cleanPath] {
			seen[cleanPath] = true
			if isDiscovered {
				discoveredFiles = append(discoveredFiles, path)
			} else {
				explicitFiles = append(explicitFiles, path)
			}
		}
	}

	// 1. Collect explicit inputs FIRST
	// For explicit files, validate schema at collection time and return error if invalid
	for _, f := range params.InputFiles {
		if err := validateSchema(f); err != nil {
			return nil, nil, []error{fmt.Errorf("explicit file %s: %v", f, err)}
		}
		addFile(f, false)
	}

	// 2. Handle recurse if RecursePath is provided
	if params.RecursePath != "" {
		err := filepath.Walk(params.RecursePath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				errors = append(errors, fmt.Errorf("error accessing path %s: %v", path, err))
				return nil
			}

			if info.IsDir() {
				// Skip common VCS and dependency directories
				name := info.Name()
				if name == ".git" || name == ".hg" || name == ".svn" ||
					name == "node_modules" || name == "vendor" || name == ".venv" {
					return filepath.SkipDir
				}
				return nil
			}

			if shouldDiscoverFile(info.Name(), params.Filename) {
				// For discovered files, apply spec-compliant handling:
				// - File without schema marker: SILENT SKIP (not our file)
				// - File with our schema but malformed/unknown version: HARD ERROR
				if err := validateSchema(path); err != nil {
					if err == ErrMissingSchema {
						// Silently skip files without our schema marker
						return nil
					}
					// Hard error for malformed files or unknown schema versions
					return fmt.Errorf("file %s: %w", path, err)
				}
				addFile(path, true)
			}

			return nil
		})

		if err != nil {
			errors = append(errors, err)
		}
	}

	return explicitFiles, discoveredFiles, errors
}

// shouldDiscoverFile checks if a file should be discovered during recursive walk.
// If using default filename, discovers both .components.json and .components.csv.
// Otherwise, matches the exact filename provided.
func shouldDiscoverFile(name, filename string) bool {
	// Default case: discover both JSON and CSV
	if filename == ".components.json" {
		return name == ".components.json" || name == ".components.csv"
	}
	// Custom filename: exact match only
	return name == filename
}

// validateSchema checks if a file has the interlynk component-manifest schema marker.
// Returns nil if valid, error with specific message otherwise.
// For JSON files: checks the "schema" field equals ComponentFileSchema.
// For CSV files: checks the first line starts with the schema marker.
func validateSchema(path string) error {
	ext := strings.ToLower(filepath.Ext(path))

	switch ext {
	case ".json":
		return validateJSONSchema(path)
	case ".csv":
		return validateCSVSchema(path)
	default:
		return fmt.Errorf("unsupported file format: %s", ext)
	}
}

// validateJSONSchema checks if a JSON file has our schema marker.
// Returns specific error for missing vs invalid schema.
func validateJSONSchema(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	var doc struct {
		Schema string `json:"schema"`
	}

	if err := json.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("failed to parse JSON: %w", err)
	}

	schema := strings.TrimSpace(doc.Schema)
	if schema == "" {
		return ErrMissingSchema
	}

	if schema != ComponentFileSchema {
		return fmt.Errorf("%w: expected %s, got %s", ErrInvalidSchema, ComponentFileSchema, schema)
	}

	return nil
}

// validateCSVSchema checks if a CSV file has our schema marker in the first line.
// Returns specific error for missing vs invalid schema.
func validateCSVSchema(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	if !scanner.Scan() {
		return fmt.Errorf("empty file")
	}

	firstLine := strings.TrimPrefix(scanner.Text(), "#")
	schema := strings.TrimSpace(firstLine)

	if schema == "" {
		return ErrMissingSchema
	}

	if schema != ComponentFileSchema {
		return fmt.Errorf("%w: expected %s, got %s", ErrInvalidSchema, ComponentFileSchema, schema)
	}

	return nil
}
