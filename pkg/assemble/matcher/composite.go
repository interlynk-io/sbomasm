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

// CompositeComponentMatcher automatically tries multiple matching strategies in priority order
// Priority: PURL (100) > CPE (90) > Name-Version (70)
type CompositeComponentMatcher struct {
	purlMatcher        ComponentMatcher
	cpeMatcher         ComponentMatcher
	nameVersionMatcher ComponentMatcher
	minConfidence      int
}

// NewCompositeComponentMatcher creates a new composite matcher with all strategies
func NewCompositeComponentMatcher(config *MatcherConfig) *CompositeComponentMatcher {
	minConfidence := 50
	strictVersion := false
	fuzzyMatch := false
	typeMatch := true

	if config != nil {
		if config.MinConfidence > 0 {
			minConfidence = config.MinConfidence
		}
		strictVersion = config.StrictVersion
		fuzzyMatch = config.FuzzyMatch
		typeMatch = config.TypeMatch
	}

	return &CompositeComponentMatcher{
		purlMatcher:        NewPurlMatcher(strictVersion),
		cpeMatcher:         NewCPEMatcher(!strictVersion), 
		nameVersionMatcher: NewNameVersionMatcher(fuzzyMatch, typeMatch),
		minConfidence:      minConfidence,
	}
}

// Match tries strategies in order: PURL -> CPE -> Name-Version
// Returns true on first successful match above minimum confidence threshold
func (c *CompositeComponentMatcher) Match(primary, secondary Component) bool {
	// Try PURL first (highest confidence)
	if c.purlMatcher.Match(primary, secondary) {
		confidence := c.purlMatcher.MatchConfidence(primary, secondary)
		if confidence >= c.minConfidence {
			return true
		}
	}

	// Try CPE second
	if c.cpeMatcher.Match(primary, secondary) {
		confidence := c.cpeMatcher.MatchConfidence(primary, secondary)
		if confidence >= c.minConfidence {
			return true
		}
	}

	// Try Name-Version last
	if c.nameVersionMatcher.Match(primary, secondary) {
		confidence := c.nameVersionMatcher.MatchConfidence(primary, secondary)
		if confidence >= c.minConfidence {
			return true
		}
	}

	return false
}

// MatchConfidence returns the highest confidence score from successful matchers
func (c *CompositeComponentMatcher) MatchConfidence(primary, secondary Component) int {
	maxConfidence := 0

	// Try PURL first
	if c.purlMatcher.Match(primary, secondary) {
		confidence := c.purlMatcher.MatchConfidence(primary, secondary)
		if confidence >= c.minConfidence && confidence > maxConfidence {
			maxConfidence = confidence
		}
	}

	// Try CPE second
	if c.cpeMatcher.Match(primary, secondary) {
		confidence := c.cpeMatcher.MatchConfidence(primary, secondary)
		if confidence >= c.minConfidence && confidence > maxConfidence {
			maxConfidence = confidence
		}
	}

	// Try Name-Version last
	if c.nameVersionMatcher.Match(primary, secondary) {
		confidence := c.nameVersionMatcher.MatchConfidence(primary, secondary)
		if confidence >= c.minConfidence && confidence > maxConfidence {
			maxConfidence = confidence
		}
	}

	return maxConfidence
}

// Strategy returns the composite strategy identifier
func (c *CompositeComponentMatcher) Strategy() string {
	return "composite"
}

// GetMatchingStrategy returns which specific strategy would be used for these components
func (c *CompositeComponentMatcher) GetMatchingStrategy(primary, secondary Component) string {
	// Try PURL first
	if c.purlMatcher.Match(primary, secondary) {
		confidence := c.purlMatcher.MatchConfidence(primary, secondary)
		if confidence >= c.minConfidence {
			return "purl"
		}
	}

	// Try CPE second
	if c.cpeMatcher.Match(primary, secondary) {
		confidence := c.cpeMatcher.MatchConfidence(primary, secondary)
		if confidence >= c.minConfidence {
			return "cpe"
		}
	}

	// Try Name-Version last
	if c.nameVersionMatcher.Match(primary, secondary) {
		confidence := c.nameVersionMatcher.MatchConfidence(primary, secondary)
		if confidence >= c.minConfidence {
			return "name-version"
		}
	}

	return "none"
}