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
	Name    string `json:"name"`
	Version string `json:"version"`
	Type    string `json:"type"`

	Description string       `json:"description,omitempty"`
	Supplier    Supplier     `json:"supplier,omitempty"`
	License     LicenseField `json:"license,omitempty"`
	PURL        string       `json:"purl,omitempty"`
	CPE         string       `json:"cpe,omitempty"`

	Hashes    []Hash    `json:"hashes,omitempty"`
	DependsOn []string  `json:"depends-on,omitempty"`
	Tags      []string  `json:"tags,omitempty"`
	Pedigree  *Pedigree `json:"pedigree,omitempty"`

	Scope        string        `json:"scope,omitempty"`
	ExternalRefs []ExternalRef `json:"external_references,omitempty"`

	// SourcePath tracks which manifest file this component came from
	// Used for vendored path detection in strict checks
	SourcePath string `json:"-"`
}

// LicenseField represents a license that can be either a string or an object.
// It supports four forms:
//   - "license": "MIT" (string/expression)
//   - "license": { "id": "MIT" } (structured)
//   - "license": { "id": "MIT", "text": "..." } (inline text)
//   - "license": { "id": "MIT", "file": "./LICENSE" } (file reference)
type LicenseField struct {
	ID   string `json:"id,omitempty"`
	Text string `json:"text,omitempty"`
	File string `json:"file,omitempty"`

	// Expression is set when license is a simple string
	Expression string `json:"-"`
}

// UnmarshalJSON implements custom unmarshaling for LicenseField.
// It handles both string and object forms.
func (l *LicenseField) UnmarshalJSON(data []byte) error {
	// Try to unmarshal as string first
	var str string
	if err := json.Unmarshal(data, &str); err == nil {
		l.Expression = str
		l.ID = ""
		l.Text = ""
		l.File = ""
		return nil
	}

	// Try to unmarshal as object
	var obj struct {
		ID   string `json:"id"`
		Text string `json:"text"`
		File string `json:"file"`
	}
	if err := json.Unmarshal(data, &obj); err != nil {
		return err
	}

	l.ID = obj.ID
	l.Text = obj.Text
	l.File = obj.File
	l.Expression = ""
	return nil
}

// IsEmpty returns true if the license field is empty
func (l LicenseField) IsEmpty() bool {
	return l.Expression == "" && l.ID == "" && l.Text == "" && l.File == ""
}

// String returns a string representation of the license
func (l LicenseField) String() string {
	if l.Expression != "" {
		return l.Expression
	}
	return l.ID
}

// Pedigree represents the provenance of a component, especially for vendored/patched code
type Pedigree struct {
	Ancestors   []Ancestor   `json:"ancestors,omitempty"`
	Descendants []Descendant `json:"descendants,omitempty"`
	Variants    []Variant    `json:"variants,omitempty"`
	Commits     []Commit     `json:"commits,omitempty"`
	Patches     []Patch      `json:"patches,omitempty"`
	Notes       string       `json:"notes,omitempty"`
}

// Ancestor represents an upstream component this was derived from
type Ancestor struct {
	PURL string `json:"purl,omitempty"`
}

// Descendant represents a downstream component derived from this
type Descendant struct {
	PURL string `json:"purl,omitempty"`
}

// Variant represents a variant of this component
type Variant struct {
	PURL string `json:"purl,omitempty"`
}

// Commit represents a specific commit in version control
type Commit struct {
	UID string `json:"uid,omitempty"`
	URL string `json:"url,omitempty"`
}

// Patch represents a patch applied to the component
type Patch struct {
	Type     string     `json:"type,omitempty"`
	Diff     Diff       `json:"diff,omitempty"`
	Resolves []Resolves `json:"resolves,omitempty"`
}

// Diff represents patch diff information
type Diff struct {
	Text string `json:"text,omitempty"`
	URL  string `json:"url,omitempty"`
}

// Resolves represents what a patch resolves (e.g., security issue)
type Resolves struct {
	Type string `json:"type,omitempty"`
	Name string `json:"name,omitempty"`
	URL  string `json:"url,omitempty"`
}

type Hash struct {
	Algorithm  string   `json:"algorithm"`
	Value      string   `json:"value"`
	File       string   `json:"file,omitempty"`
	Path       string   `json:"path,omitempty"`
	Extensions []string `json:"extensions,omitempty"`
}

// ParseComponentFiles takes a list of file paths, parses each file and extracts components.
// Schema validation is assumed to have been done at file collection time.
// Returns a list of component lists (one per file) and any parsing errors.
func ParseComponentFiles(files []string) ([][]Component, []error) {
	var allComponentsFromFiles [][]Component
	var errors []error

	for _, file := range files {
		components, err := parseComponents(file)
		if err != nil {
			errors = append(errors, fmt.Errorf("file %s: %v", file, err))
			continue
		}

		// Set SourcePath on each component to track which file it came from
		for i := range components {
			components[i].SourcePath = file
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

// parseComponents determines the file format based on the extension
// and calls the appropriate parser.
func parseComponents(path string) ([]Component, error) {

	switch strings.ToLower(filepath.Ext(path)) {
	case ".json":
		return parseJSONComponents(path)
	case ".csv":
		return parseCSVComponents(path)
	default:
		return nil, fmt.Errorf("unsupported file format: %s", path)
	}
}

type componentJSON struct {
	Schema     string      `json:"schema"`
	Components []Component `json:"components"`
}

// parseJSONComponents reads a JSON file and
// unmarshals into a list of components.
// Validates each component has required fields.
func parseJSONComponents(path string) ([]Component, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var doc componentJSON
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}

	// Validate and sanitize components
	return SanitizeAndValidateComponents(doc.Components, path)
}

// parseCSVComponents reads a CSV file and parses it into a list of components.
// The first line must be the schema marker,
// and the second line must be column headers.
// Validates each component has required fields.
func parseCSVComponents(path string) ([]Component, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	reader := csv.NewReader(file)
	reader.FieldsPerRecord = -1 // Allow variable-length rows for optional fields

	// First line = schema marker (already validated at collection time)
	// Skip it and move to column headers
	_, err = reader.Read()
	if err != nil {
		return nil, err
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
	rowNum := 2 // Start at 2 (after schema line and header)

	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		rowNum++

		// Skip empty rows
		if len(record) == 0 || (len(record) == 1 && strings.TrimSpace(record[0]) == "") {
			continue
		}

		c := Component{
			Name:        getValue("name", record, colIndex),
			Version:     getValue("version", record, colIndex),
			Type:        getValue("type", record, colIndex),
			Description: getValue("description", record, colIndex),
			License:     LicenseField{Expression: getValue("license", record, colIndex)},
			PURL:        getValue("purl", record, colIndex),
			CPE:         getValue("cpe", record, colIndex),
			Scope:       getValue("scope", record, colIndex),
			Supplier:    parseSupplierFromCSV(record, colIndex),
			Hashes:      parseHashesFromCSV(record, colIndex),
		}

		c.DependsOn = parseDependsOnFromCSV(record, colIndex)
		c.Tags = parseTagsFromCSV(record, colIndex)
		c.ExternalRefs = parseExternalRefsFromCSV(record, colIndex)

		// Validate component (sanitization happens in ValidateComponent)
		if err := ValidateComponent(c, rowNum-3, path); err != nil {
			// Adjust index to reflect data row (subtract schema + header rows)
			return nil, fmt.Errorf("row %d: %w", rowNum, err)
		}

		components = append(components, c)
	}

	return components, nil
}

// parseSupplierFromCSV extracts supplier information from CSV record.
func parseSupplierFromCSV(record []string, colIndex map[string]int) Supplier {
	return Supplier{
		Name:  getValue("supplier_name", record, colIndex),
		Email: getValue("supplier_email", record, colIndex),
		URL:   getValue("supplier_url", record, colIndex),
	}
}

// parseExternalRefsFromCSV extracts external references from CSV record.
// Format: "type:url:comment,type:url:comment"
func parseExternalRefsFromCSV(record []string, colIndex map[string]int) []ExternalRef {
	v := getValue("external_references", record, colIndex)
	if v == "" {
		return nil
	}

	var refs []ExternalRef
	raw := strings.Split(v, "|")

	for _, r := range raw {
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}

		// Format: type:url or type:url:comment
		parts := strings.SplitN(r, ":", 3)
		if len(parts) >= 2 {
			ref := ExternalRef{
				Type: parts[0],
				URL:  parts[1],
			}
			if len(parts) >= 3 {
				ref.Comment = parts[2]
			}
			refs = append(refs, ref)
		}
	}

	return refs
}

// parseDependsOnFromCSV extracts `depends-on` information from CSV record.
func parseDependsOnFromCSV(record []string, colIndex map[string]int) []string {
	v := getValue("depends_on", record, colIndex)

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
// Supports both explicit hash_value and hash_file for computed hashes.
func parseHashesFromCSV(record []string, colIndex map[string]int) []Hash {
	v := getValue("hash_value", record, colIndex)
	file := getValue("hash_file", record, colIndex)
	algo := getValue("hash_algorithm", record, colIndex)

	if v != "" {
		return []Hash{
			{
				Algorithm: algo,
				Value:     v,
			},
		}
	}

	if file != "" {
		return []Hash{
			{
				Algorithm: algo,
				File:      file,
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
