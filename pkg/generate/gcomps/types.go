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

import "context"

// GenerateComponentsParams holds the parameters for the generate components command
type GenerateComponentsParams struct {
	Ctx *context.Context

	// Output is the path to the output file.
	// If not provided, defaults to ".components.json" in current directory.
	Output string

	// CSV indicates whether to generate CSV format instead of JSON.
	CSV bool

	// Force indicates whether to overwrite existing files.
	Force bool

	// Describe indicates whether to print human-readable field descriptions.
	Describe bool

	// Schema indicates whether to print the JSON Schema.
	Schema bool
}

// NewGenerateComponentsParams creates a new instance of
// GenerateComponentsParams with default values.
func NewGenerateComponentsParams() *GenerateComponentsParams {
	return &GenerateComponentsParams{}
}

// Component represents a single component in the manifest
type Component struct {
	Name         string        `json:"name"`
	Version      string        `json:"version"`
	Type         string        `json:"type"`
	Description  string        `json:"description,omitempty"`
	Supplier     *Supplier     `json:"supplier,omitempty"`
	License      string        `json:"license,omitempty"`
	PURL         string        `json:"purl,omitempty"`
	CPE          string        `json:"cpe,omitempty"`
	ExternalRefs []ExternalRef `json:"external_references,omitempty"`
	Hashes       []Hash        `json:"hashes,omitempty"`
	Scope        string        `json:"scope,omitempty"`
	DependsOn    []string      `json:"depends_on,omitempty"`
	Tags         []string      `json:"tags,omitempty"`
}

// Supplier represents the supplier of a component
type Supplier struct {
	Name  string `json:"name,omitempty"`
	Email string `json:"email,omitempty"`
	URL   string `json:"url,omitempty"`
}

// ExternalRef represents an external reference
type ExternalRef struct {
	Type    string `json:"type"`
	URL     string `json:"url"`
	Comment string `json:"comment,omitempty"`
}

// Hash represents a file hash
type Hash struct {
	Algorithm string `json:"algorithm"`
	Value     string `json:"value"`
	File      string `json:"file,omitempty"`
}

// Manifest represents the root of a component manifest file
type Manifest struct {
	Schema     string      `json:"schema"`
	Components []Component `json:"components"`
}
