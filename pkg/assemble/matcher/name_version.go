// Copyright 2025 Interlynk.io
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package matcher

import (
	"strings"
)

// NameVersionMatcher matches components based on name and version
type NameVersionMatcher struct {
	fuzzyMatch bool // allow fuzzy name matching
	typeMatch  bool // also require component type to match
}

// NewNameVersionMatcher creates a new NameVersionMatcher
func NewNameVersionMatcher(fuzzyMatch, typeMatch bool) ComponentMatcher {
	return &NameVersionMatcher{
		fuzzyMatch: fuzzyMatch,
		typeMatch:  typeMatch,
	}
}

// Match determines if two components match based on name and version
func (m *NameVersionMatcher) Match(primary, secondary Component) bool {
	primaryName := m.normalizeName(primary.GetName())
	secondaryName := m.normalizeName(secondary.GetName())

	// Names must match
	if !m.namesMatch(primaryName, secondaryName) {
		return false
	}

	// Versions must match
	primaryVersion := m.normalizeVersion(primary.GetVersion())
	secondaryVersion := m.normalizeVersion(secondary.GetVersion())
	
	if primaryVersion != secondaryVersion {
		return false
	}

	// If type matching is enabled, types must also match
	if m.typeMatch {
		primaryType := strings.ToLower(primary.GetType())
		secondaryType := strings.ToLower(secondary.GetType())
		if primaryType != "" && secondaryType != "" && primaryType != secondaryType {
			return false
		}
	}

	return true
}

// MatchConfidence returns the confidence score for name-version matching
func (m *NameVersionMatcher) MatchConfidence(primary, secondary Component) int {
	if !m.Match(primary, secondary) {
		return 0
	}
	
	confidence := 70 // Base confidence for name-version match
	
	// Higher confidence if types also match
	if m.typeMatch && primary.GetType() == secondary.GetType() {
		confidence += 10
	}
	
	// Lower confidence if fuzzy matching was used
	if m.fuzzyMatch {
		primaryName := m.normalizeName(primary.GetName())
		secondaryName := m.normalizeName(secondary.GetName())
		if primaryName != secondaryName {
			confidence -= 10
		}
	}
	
	return confidence
}

// Strategy returns the name of this matching strategy
func (m *NameVersionMatcher) Strategy() string {
	return "name-version"
}

// normalizeName normalizes a component name for comparison
func (m *NameVersionMatcher) normalizeName(name string) string {
	// Convert to lowercase and trim spaces
	name = strings.ToLower(strings.TrimSpace(name))
	
	// Remove common separators and replace with consistent ones
	name = strings.ReplaceAll(name, "_", "-")
	name = strings.ReplaceAll(name, ".", "-")
	
	return name
}

// normalizeVersion normalizes a version string for comparison
func (m *NameVersionMatcher) normalizeVersion(version string) string {
	// Trim spaces and convert to lowercase
	version = strings.ToLower(strings.TrimSpace(version))
	
	// Remove common version prefixes
	version = strings.TrimPrefix(version, "v")
	version = strings.TrimPrefix(version, "version")
	version = strings.TrimPrefix(version, "ver")
	version = strings.TrimSpace(version)
	
	return version
}

// namesMatch checks if two normalized names match
func (m *NameVersionMatcher) namesMatch(name1, name2 string) bool {
	if name1 == name2 {
		return true
	}
	
	if !m.fuzzyMatch {
		return false
	}
	
	// Fuzzy matching: check if one name contains the other
	// This helps with cases like "apache-commons-lang3" vs "commons-lang3"
	if len(name1) > len(name2) {
		return strings.Contains(name1, name2)
	}
	return strings.Contains(name2, name1)
}