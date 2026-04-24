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
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ProcessLicenses processes license information for all components:
// 1. Loads license text from disk when license.file is specified
// 2. Populates license.text from the file content
// Returns any errors encountered.
func ProcessLicenses(components []Component, manifestDir string) []error {
	var errors []error

	for i := range components {
		comp := &components[i]

		// Skip if no license file specified or text already present
		if comp.License.File == "" || comp.License.Text != "" {
			continue
		}

		// Load license file
		licensePath := strings.TrimPrefix(comp.License.File, "./")
		fullPath := filepath.Join(manifestDir, licensePath)

		data, err := os.ReadFile(fullPath)
		if err != nil {
			errors = append(errors, fmt.Errorf("component %s@%s: failed to read license file '%s': %w",
				comp.Name, comp.Version, fullPath, err))
			continue
		}

		// Populate the text field
		comp.License.Text = string(data)
	}

	return errors
}
