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

// PurlMatcher matches components based on Package URL (purl)
type PurlMatcher struct {
	strictVersion bool // if false, ignores version in comparison
}

// NewPurlMatcher creates a new PurlMatcher
func NewPurlMatcher(strictVersion bool) ComponentMatcher {
	return &PurlMatcher{
		strictVersion: strictVersion,
	}
}

// Match determines if two components match based on their purls
func (m *PurlMatcher) Match(primary, secondary Component) bool {
	primaryPurl := primary.GetPurl()
	secondaryPurl := secondary.GetPurl()

	// Both must have purls to match
	if primaryPurl == "" || secondaryPurl == "" {
		return false
	}

	// Normalize purls for comparison
	primaryPurl = m.normalizePurl(primaryPurl)
	secondaryPurl = m.normalizePurl(secondaryPurl)

	if !m.strictVersion {
		// Remove version from comparison
		primaryPurl = m.removeVersion(primaryPurl)
		secondaryPurl = m.removeVersion(secondaryPurl)
	}

	return primaryPurl == secondaryPurl
}

// MatchConfidence returns the confidence score for purl matching
func (m *PurlMatcher) MatchConfidence(primary, secondary Component) int {
	if !m.Match(primary, secondary) {
		return 0
	}
	// Purl matching is very precise
	return 100
}

// Strategy returns the name of this matching strategy
func (m *PurlMatcher) Strategy() string {
	return "purl"
}

// normalizePurl normalizes a purl for comparison
func (m *PurlMatcher) normalizePurl(purl string) string {
	// Convert to lowercase for case-insensitive comparison
	purl = strings.ToLower(strings.TrimSpace(purl))
	
	// Remove any trailing slashes
	purl = strings.TrimRight(purl, "/")
	
	// Handle pkg: prefix
	if !strings.HasPrefix(purl, "pkg:") {
		return purl
	}
	
	return purl
}

// removeVersion removes the version part from a purl
func (m *PurlMatcher) removeVersion(purl string) string {
	// Purl format: pkg:type/namespace/name@version?qualifiers#subpath
	// We want to remove @version part
	
	atIndex := strings.Index(purl, "@")
	if atIndex == -1 {
		return purl
	}
	
	// Find the end of version (could be followed by ? or #)
	afterVersion := purl[atIndex:]
	qualifierIndex := strings.Index(afterVersion, "?")
	subpathIndex := strings.Index(afterVersion, "#")
	
	endIndex := len(afterVersion)
	if qualifierIndex != -1 && (subpathIndex == -1 || qualifierIndex < subpathIndex) {
		endIndex = qualifierIndex
	} else if subpathIndex != -1 {
		endIndex = subpathIndex
	}
	
	// Reconstruct without version
	return purl[:atIndex] + afterVersion[endIndex:]
}