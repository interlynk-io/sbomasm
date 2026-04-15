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

		c := Component{
			Name:     record[colIndex["name"]],
			Version:  record[colIndex["version"]],
			Type:     record[colIndex["type"]],
			License:  record[colIndex["license"]],
			PURL:     record[colIndex["purl"]],
			CPE:      record[colIndex["cpe"]],
			Supplier: parseSupplierFromCSV(record, colIndex),
			Hashes:   parseHashesFromCSV(record, colIndex),
		}

		// dependency_of
		if v := record[colIndex["dependency_of"]]; v != "" {
			c.DependencyOf = strings.Split(v, ",")
		}

		// tags
		if v := record[colIndex["tags"]]; v != "" {
			raw := strings.Split(v, ",")
			var cleaned []string
			for _, r := range raw {
				t := strings.TrimSpace(r)
				if t != "" {
					cleaned = append(cleaned, t)
				}
			}
			c.Tags = cleaned
			// c.Tags = strings.Split(v, ",")
		}

		components = append(components, c)
	}

	return components, nil
}

func parseSupplierFromCSV(record []string, colIndex map[string]int) Supplier {
	return Supplier{
		Name:  record[colIndex["supplier_name"]],
		Email: record[colIndex["supplier_email"]],
	}
}

func parseHashesFromCSV(record []string, colIndex map[string]int) []Hash {
	v := record[colIndex["hash_value"]]
	if v != "" {
		return []Hash{
			{
				Algorithm: record[colIndex["hash_algorithm"]],
				Value:     v,
			},
		}
	}
	return nil
}
