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
	"context"
)

type GenerateSBOMParams struct {
	Ctx *context.Context

	// ConfigPath is the path to the artifact metadata config file
	// (e.g., `.artifact-metadata.yaml`).
	// By default, it looks for `.artifact-metadata.yaml` in the current working directory
	ConfigPath string

	// InputFiles can be explicitly provided or collected recursively from a specified path
	InputFiles []string

	// Output is the path to the output SBOM file.
	// If not provided, it defaults to stdout.
	Output string

	// Tags and ExcludeTags are used to filter components based on their tags.
	// If Tags is provided, only components that have at least one of the
	// specified tags will be included in the final SBOM.
	Tags []string

	// If ExcludeTags is provided, any component that has at  least one
	// of the specified exclude tags will be excluded from the final SBOM.
	ExcludeTags []string

	// Format specifies the output SBOM format (e.g., "cyclonedx", "spdx").
	// Defaults to "cyclonedx" if not provided.
	Format string

	// RecursePath is the path to recursively search for
	// component files (e.g., `.components.json`).
	RecursePath string

	// Filename is the filename of input component file (e.g., `.components.json`).
	Filename string
}

// NewGenerateSBOMParams creates a new instance of
// GenerateSBOMParams with default values.
func NewGenerateSBOMParams() *GenerateSBOMParams {
	return &GenerateSBOMParams{}
}

// Artifact represents the primary component information of the SBOM,
// which is typically the main application.
// It includes metadata such as name, version, description, primary purpose,
// supplier information, authors, license, and other relevant details.
type Artifact struct {
	Name           string // required
	Version        string // required
	Description    string // optional
	PrimaryPurpose string // required, e.g., "application", "library", "container", etc.

	Supplier Supplier
	Authors  []Author

	LicenseID string
	PURL      string
	CPE       string
	Copyright string
}

type Author struct {
	Name  string
	Email string
}

type Supplier struct {
	Name  string
	Email string
}
