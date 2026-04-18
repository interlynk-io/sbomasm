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

// ProcessPedigrees processes pedigree information for all components:
// 1. Loads patch files from disk (diff.url -> diff.text)
// 2. Validates that component purl != ancestor purl (hard error)
// Returns any errors encountered.
func ProcessPedigrees(components []Component, manifestDir string) []error {
	var errors []error

	for _, comp := range components {
		if comp.Pedigree == nil {
			continue
		}

		compKey := componentKey(comp)

		// Validate purl doesn't equal any ancestor purl (hard error per spec)
		if err := validatePurlVsAncestors(comp); err != nil {
			errors = append(errors, fmt.Errorf("component %s: %w", compKey, err))
			continue
		}

		// Load patch files
		for i := range comp.Pedigree.Patches {
			patch := &comp.Pedigree.Patches[i]
			if err := loadPatchDiff(patch, manifestDir); err != nil {
				errors = append(errors, fmt.Errorf("component %s: failed to load patch: %w", compKey, err))
			}
		}
	}

	return errors
}

// validatePurlVsAncestors checks that a component's purl doesn't equal any ancestor purl.
// This is always a hard error (even without --strict) because it's a correctness bug.
func validatePurlVsAncestors(comp Component) error {
	if comp.Pedigree == nil || comp.PURL == "" {
		return nil
	}

	for _, ancestor := range comp.Pedigree.Ancestors {
		if ancestor.PURL == comp.PURL {
			return fmt.Errorf("purl '%s' collides with pedigree.ancestors[].purl: a patched component must have a different purl from its upstream ancestor", comp.PURL)
		}
	}

	return nil
}

// loadPatchDiff loads a patch diff file from disk if the URL is a relative path.
// If the URL is http(s)://, it's left as-is (not fetched).
// If the URL is a relative file path, the file is read and inlined as text.
func loadPatchDiff(patch *Patch, manifestDir string) error {
	url := strings.TrimSpace(patch.Diff.URL)
	if url == "" {
		return nil
	}

	// If already has text, skip loading
	if patch.Diff.Text != "" {
		return nil
	}

	// If it's an HTTP URL, leave it as-is (don't fetch)
	if strings.HasPrefix(url, "http://") || strings.HasPrefix(url, "https://") {
		return nil
	}

	// It's a relative path - load the file
	path := strings.TrimPrefix(url, "./")
	fullPath := filepath.Join(manifestDir, path)

	data, err := os.ReadFile(fullPath)
	if err != nil {
		return fmt.Errorf("failed to read patch file '%s': %w", fullPath, err)
	}

	patch.Diff.Text = string(data)
	return nil
}
