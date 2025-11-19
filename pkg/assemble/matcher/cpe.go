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

// CPEMatcher matches components based on Common Platform Enumeration (CPE)
type CPEMatcher struct {
	ignoreVersion bool // if true, ignores version in comparison
}

// NewCPEMatcher creates a new CPEMatcher
func NewCPEMatcher(ignoreVersion bool) ComponentMatcher {
	return &CPEMatcher{
		ignoreVersion: ignoreVersion,
	}
}

// Match determines if two components match based on their CPEs
func (m *CPEMatcher) Match(primary, secondary Component) bool {
	primaryCPE := primary.GetCPE()
	secondaryCPE := secondary.GetCPE()

	// Both must have CPEs to match
	if primaryCPE == "" || secondaryCPE == "" {
		return false
	}

	// Normalize CPEs for comparison
	primaryCPE = m.normalizeCPE(primaryCPE)
	secondaryCPE = m.normalizeCPE(secondaryCPE)

	if m.ignoreVersion {
		// Remove version from comparison
		primaryCPE = m.removeVersion(primaryCPE)
		secondaryCPE = m.removeVersion(secondaryCPE)
	}

	return primaryCPE == secondaryCPE
}

// MatchConfidence returns the confidence score for CPE matching
func (m *CPEMatcher) MatchConfidence(primary, secondary Component) int {
	if !m.Match(primary, secondary) {
		return 0
	}
	// CPE matching is fairly precise but not as precise as purl
	return 90
}

// Strategy returns the name of this matching strategy
func (m *CPEMatcher) Strategy() string {
	return "cpe"
}

// normalizeCPE normalizes a CPE string for comparison
func (m *CPEMatcher) normalizeCPE(cpe string) string {
	// Convert to lowercase for case-insensitive comparison
	cpe = strings.ToLower(strings.TrimSpace(cpe))

	// Handle both CPE 2.2 (cpe:/...) and CPE 2.3 (cpe:2.3:...) formats
	// Convert CPE 2.2 to 2.3 format for uniform comparison
	if strings.HasPrefix(cpe, "cpe:/") {
		cpe = m.convertCPE22to23(cpe)
	}

	return cpe
}

// convertCPE22to23 converts CPE 2.2 format to CPE 2.3 format
func (m *CPEMatcher) convertCPE22to23(cpe22 string) string {
	// CPE 2.2: cpe:/part:vendor:product:version:update:edition:language
	// CPE 2.3: cpe:2.3:part:vendor:product:version:update:edition:language:*:*:*:*

	if !strings.HasPrefix(cpe22, "cpe:/") {
		return cpe22
	}

	// Remove "cpe:/" prefix and split
	parts := strings.Split(strings.TrimPrefix(cpe22, "cpe:/"), ":")

	// Pad with wildcards to make 11 parts (part + 10 attributes)
	for len(parts) < 11 {
		parts = append(parts, "*")
	}

	// Reconstruct as CPE 2.3
	return "cpe:2.3:" + strings.Join(parts, ":")
}

// removeVersion removes the version part from a CPE
func (m *CPEMatcher) removeVersion(cpe string) string {
	parts := strings.Split(cpe, ":")

	// CPE 2.3 format has version at index 5 (0-based)
	// cpe:2.3:part:vendor:product:version:...
	if len(parts) > 5 {
		parts[5] = "*" // Replace version with wildcard
	}

	return strings.Join(parts, ":")
}
