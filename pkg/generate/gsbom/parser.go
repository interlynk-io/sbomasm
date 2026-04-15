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
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	ComponentFileSchema = "interlynk/component-manifest/v1"
)

type Component struct {
	Name         string   `json:"name"`
	Version      string   `json:"version"`
	Type         string   `json:"type"`
	Supplier     Supplier `json:"supplier"`
	License      string   `json:"license"`
	PURL         string   `json:"purl"`
	CPE          string   `json:"cpe"`
	Hashes       []Hash   `json:"hashes"`
	DependencyOf []string `json:"dependency-of"`
	Tags         []string `json:"tags"`
}

type Hash struct {
	Algorithm string `json:"algorithm"`
	Value     string `json:"value"`
}

// ParseComponentFiles perform following fucntionality:
// - takes a list of file paths,
// - parses each file and extract components and
// - returns a list of components from all files.
func ParseComponentFiles(files []string) ([][]Component, []error) {
	var allComponentsFromFiles [][]Component
	var errors []error

	for _, file := range files {
		components, err := parseFile(file)
		if err != nil {
			errors = append(errors, fmt.Errorf("file %s: %v", file, err))
			continue
		}
		allComponentsFromFiles = append(allComponentsFromFiles, components)
	}

	/*
		allComponentsByFiles =
			[
			  [c1, c2],      // file1
			  [c3],          // file2
			  [c4, c5, c6],  // file3
			]
	*/
	return allComponentsFromFiles, errors
}

// parseFile determines the file format based on the extension
// and calls the appropriate parser.
func parseFile(path string) ([]Component, error) {

	switch strings.ToLower(filepath.Ext(path)) {
	case ".json":
		return parseJSON(path)
	case ".csv":
		return parseCSV(path)
	default:
		return nil, fmt.Errorf("unsupported file format: %s", path)
	}
}

type componentJSON struct {
	Schema     string      `json:"schema"`
	Components []Component `json:"components"`
}

// parseJSON reads a JSON file and
// unmarshals into a list of components.
func parseJSON(path string) ([]Component, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var doc componentJSON
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}

	if strings.TrimSpace(doc.Schema) == "" {
		return nil, fmt.Errorf("missing schema marker in JSON file")
	}

	// Validate schema marker
	if doc.Schema != ComponentFileSchema {
		return nil, fmt.Errorf("invalid schema: expected %s, got %s", ComponentFileSchema, doc.Schema)
	}

	return doc.Components, nil
}

// parseCSV reads a CSV file and parses it into a list of components.
// The first line must be the schema marker,
// and the second line must be column headers.
func parseCSV(path string) ([]Component, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	reader := csv.NewReader(file)
	reader.FieldsPerRecord = -1 // Allow variable-length rows for optional fields

	// First line = schema marker
	header, err := reader.Read()
	if err != nil {
		return nil, err
	}

	// let's remove "#" from header[0]
	if len(header) > 0 {
		header[0] = strings.TrimPrefix(header[0], "#")
	}

	if len(header) == 0 || header[0] != ComponentFileSchema {
		return nil, fmt.Errorf("invalid schema marker: expected %s, got %s", ComponentFileSchema, header[0])
	}

	// Next line = column headers
	columns, err := reader.Read()
	if err != nil {
		return nil, err
	}

	colIndex := make(map[string]int)
	for i, col := range columns {
		colIndex[col] = i
	}

	var components []Component

	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		// Skip empty rows
		if len(record) == 0 || (len(record) == 1 && strings.TrimSpace(record[0]) == "") {
			continue
		}

		c := Component{
			Name:     getValue("name", record, colIndex),
			Version:  getValue("version", record, colIndex),
			Type:     getValue("type", record, colIndex),
			License:  getValue("license", record, colIndex),
			PURL:     getValue("purl", record, colIndex),
			CPE:      getValue("cpe", record, colIndex),
			Supplier: parseSupplierFromCSV(record, colIndex),
			Hashes:   parseHashesFromCSV(record, colIndex),
		}

		// Skip rows with no name/version (likely empty/malformed)
		if c.Name == "" && c.Version == "" {
			continue
		}

		c.DependencyOf = parseDependencyOfFromCSV(record, colIndex)
		c.Tags = parseTagsFromCSV(record, colIndex)

		components = append(components, c)
	}

	return components, nil
}

// parseSupplierFromCSV extracts supplier information from CSV record.
func parseSupplierFromCSV(record []string, colIndex map[string]int) Supplier {
	return Supplier{
		Name:  getValue("supplier_name", record, colIndex),
		Email: getValue("supplier_email", record, colIndex),
	}
}

// parseDependencyOfFromCSV extracts `dependency-of“ information from CSV record.
func parseDependencyOfFromCSV(record []string, colIndex map[string]int) []string {
	v := getValue("dependency_of", record, colIndex)

	if v == "" {
		return nil
	}

	raw := strings.Split(v, ",")

	var allDeps []string
	for _, r := range raw {
		t := strings.TrimSpace(r)
		if t != "" {
			allDeps = append(allDeps, t)
		}
	}
	return allDeps
}

// parseTagsFromCSV extracts tags information from CSV record.
func parseTagsFromCSV(record []string, colIndex map[string]int) []string {
	v := getValue("tags", record, colIndex)

	if v == "" {
		return nil
	}

	raw := strings.Split(v, ",")

	var allTags []string
	for _, r := range raw {
		t := strings.TrimSpace(r)
		if t != "" {
			allTags = append(allTags, t)
		}
	}
	return allTags
}

// parseHashesFromCSV extracts hash information from CSV record.
func parseHashesFromCSV(record []string, colIndex map[string]int) []Hash {
	v := getValue("hash_value", record, colIndex)

	if v != "" {
		return []Hash{
			{
				Algorithm: getValue("hash_algorithm", record, colIndex),
				Value:     v,
			},
		}
	}
	return nil
}

// getValue is a helper function to safely extract column values from a CSV record.
func getValue(colName string, record []string, colIndex map[string]int) string {
	idx, ok := colIndex[colName]
	if !ok || idx >= len(record) {
		return ""
	}
	return record[idx]
}
