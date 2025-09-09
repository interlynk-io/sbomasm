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

// ComponentIndex provides efficient lookup for component matching
type ComponentIndex struct {
	components   []Component
	purlIndex    map[string][]int // purl -> component indices
	cpeIndex     map[string][]int // cpe -> component indices
	nameIndex    map[string][]int // name -> component indices
	versionIndex map[string][]int // version -> component indices
}

// NewComponentIndex creates a new empty ComponentIndex
func NewComponentIndex() *ComponentIndex {
	return &ComponentIndex{
		components:   []Component{},
		purlIndex:    make(map[string][]int),
		cpeIndex:     make(map[string][]int),
		nameIndex:    make(map[string][]int),
		versionIndex: make(map[string][]int),
	}
}

// BuildIndex creates indices for fast lookup from a list of components
func BuildIndex(components []Component) *ComponentIndex {
	idx := NewComponentIndex()
	
	for i, comp := range components {
		idx.components = append(idx.components, comp)
		
		// Index by purl
		if purl := comp.GetPurl(); purl != "" {
			normalizedPurl := strings.ToLower(strings.TrimSpace(purl))
			idx.purlIndex[normalizedPurl] = append(idx.purlIndex[normalizedPurl], i)
		}
		
		// Index by CPE
		if cpe := comp.GetCPE(); cpe != "" {
			normalizedCPE := strings.ToLower(strings.TrimSpace(cpe))
			idx.cpeIndex[normalizedCPE] = append(idx.cpeIndex[normalizedCPE], i)
		}
		
		// Index by name
		if name := comp.GetName(); name != "" {
			normalizedName := strings.ToLower(strings.TrimSpace(name))
			idx.nameIndex[normalizedName] = append(idx.nameIndex[normalizedName], i)
		}
		
		// Index by version
		if version := comp.GetVersion(); version != "" {
			normalizedVersion := strings.ToLower(strings.TrimSpace(version))
			idx.versionIndex[normalizedVersion] = append(idx.versionIndex[normalizedVersion], i)
		}
	}
	
	return idx
}

// AddComponent adds a component to the index
func (idx *ComponentIndex) AddComponent(comp Component) {
	i := len(idx.components)
	idx.components = append(idx.components, comp)
	
	// Update indices
	if purl := comp.GetPurl(); purl != "" {
		normalizedPurl := strings.ToLower(strings.TrimSpace(purl))
		idx.purlIndex[normalizedPurl] = append(idx.purlIndex[normalizedPurl], i)
	}
	
	if cpe := comp.GetCPE(); cpe != "" {
		normalizedCPE := strings.ToLower(strings.TrimSpace(cpe))
		idx.cpeIndex[normalizedCPE] = append(idx.cpeIndex[normalizedCPE], i)
	}
	
	if name := comp.GetName(); name != "" {
		normalizedName := strings.ToLower(strings.TrimSpace(name))
		idx.nameIndex[normalizedName] = append(idx.nameIndex[normalizedName], i)
	}
	
	if version := comp.GetVersion(); version != "" {
		normalizedVersion := strings.ToLower(strings.TrimSpace(version))
		idx.versionIndex[normalizedVersion] = append(idx.versionIndex[normalizedVersion], i)
	}
}

// FindMatches returns all matching components using the given matcher
func (idx *ComponentIndex) FindMatches(component Component, matcher ComponentMatcher) []MatchResult {
	results := []MatchResult{}
	
	// Get candidate indices based on matcher strategy
	candidateIndices := idx.getCandidateIndices(component, matcher.Strategy())
	
	// Check each candidate for actual match
	seen := make(map[int]bool)
	for _, i := range candidateIndices {
		if seen[i] {
			continue
		}
		seen[i] = true
		
		candidate := idx.components[i]
		if matcher.Match(candidate, component) {
			results = append(results, MatchResult{
				Matched:    true,
				Confidence: matcher.MatchConfidence(candidate, component),
				Strategy:   matcher.Strategy(),
				Primary:    candidate,
				Secondary:  component,
			})
		}
	}
	
	return results
}

// FindBestMatch returns the best matching component or nil if no match
func (idx *ComponentIndex) FindBestMatch(component Component, matcher ComponentMatcher) *MatchResult {
	matches := idx.FindMatches(component, matcher)
	if len(matches) == 0 {
		return nil
	}
	
	// Find match with highest confidence
	best := &matches[0]
	for i := 1; i < len(matches); i++ {
		if matches[i].Confidence > best.Confidence {
			best = &matches[i]
		}
	}
	
	return best
}

// getCandidateIndices returns indices of components that might match
func (idx *ComponentIndex) getCandidateIndices(component Component, strategy string) []int {
	switch strategy {
	case "purl":
		if purl := component.GetPurl(); purl != "" {
			normalizedPurl := strings.ToLower(strings.TrimSpace(purl))
			// Also check without version
			withoutVersion := removeVersionFromPurl(normalizedPurl)
			indices := []int{}
			indices = append(indices, idx.purlIndex[normalizedPurl]...)
			for p, idxs := range idx.purlIndex {
				if removeVersionFromPurl(p) == withoutVersion {
					indices = append(indices, idxs...)
				}
			}
			return indices
		}
		
	case "cpe":
		if cpe := component.GetCPE(); cpe != "" {
			normalizedCPE := strings.ToLower(strings.TrimSpace(cpe))
			return idx.cpeIndex[normalizedCPE]
		}
		
	case "name-version":
		if name := component.GetName(); name != "" {
			normalizedName := strings.ToLower(strings.TrimSpace(name))
			return idx.nameIndex[normalizedName]
		}
	}
	
	// If no specific index available, return all components
	indices := make([]int, len(idx.components))
	for i := range indices {
		indices[i] = i
	}
	return indices
}

// GetAllComponents returns all components in the index
func (idx *ComponentIndex) GetAllComponents() []Component {
	return idx.components
}

// Size returns the number of components in the index
func (idx *ComponentIndex) Size() int {
	return len(idx.components)
}

// removeVersionFromPurl is a helper to remove version from purl for indexing
func removeVersionFromPurl(purl string) string {
	atIndex := strings.Index(purl, "@")
	if atIndex == -1 {
		return purl
	}
	
	afterVersion := purl[atIndex:]
	qualifierIndex := strings.Index(afterVersion, "?")
	subpathIndex := strings.Index(afterVersion, "#")
	
	endIndex := len(afterVersion)
	if qualifierIndex != -1 && (subpathIndex == -1 || qualifierIndex < subpathIndex) {
		endIndex = qualifierIndex
	} else if subpathIndex != -1 {
		endIndex = subpathIndex
	}
	
	return purl[:atIndex] + afterVersion[endIndex:]
}