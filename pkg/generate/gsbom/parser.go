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
	"strings"
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

func ParseComponentFiles(files []string) ([][]Component, []error) {
	var allComponentsByFiles [][]Component
	var warnings []error

	for _, file := range files {
		listComponentsInFile, err := parseFile(file)
		if err != nil {
			warnings = append(warnings, fmt.Errorf("file %s: %v", file, err))
			continue
		}

		allComponentsByFiles = append(allComponentsByFiles, listComponentsInFile) // keep per-file grouping
	}

	/*
		allComponentsByFiles =
			[
			  [c1, c2],      // file1
			  [c3],          // file2
			  [c4, c5, c6],  // file3
			]
	*/
	return allComponentsByFiles, warnings
}

func parseFile(path string) ([]Component, error) {
	switch {
	case strings.HasSuffix(path, ".json"):
		return parseJSON(path)
	case strings.HasSuffix(path, ".csv"):
		return parseCSV(path)
	default:
		return nil, fmt.Errorf("unsupported file format")
	}
}

type componentJSON struct {
	Schema     string      `json:"schema"`
	Components []Component `json:"components"`
}

func parseJSON(path string) ([]Component, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var doc componentJSON
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}

	if doc.Schema != "interlynk/component-manifest/v1" {
		return nil, fmt.Errorf("invalid schema")
	}

	return doc.Components, nil
}

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

	if len(header) == 0 || header[0] != "#interlynk/component-manifest/v1" {
		return nil, fmt.Errorf("invalid schema marker")
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
			Name:    record[colIndex["name"]],
			Version: record[colIndex["version"]],
			Type:    record[colIndex["type"]],
			License: record[colIndex["license"]],
			PURL:    record[colIndex["purl"]],
			CPE:     record[colIndex["cpe"]],
		}

		// dependency_of
		if v := record[colIndex["dependency_of"]]; v != "" {
			c.DependencyOf = strings.Split(v, ",")
		}

		// tags
		if v := record[colIndex["tags"]]; v != "" {
			c.Tags = strings.Split(v, ",")
		}

		components = append(components, c)
	}

	return components, nil
}
