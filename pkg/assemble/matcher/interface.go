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
	"fmt"
)

// ComponentMatcher defines the interface for matching components across SBOMs
type ComponentMatcher interface {
	// Match determines if two components are the same based on the strategy
	Match(primary, secondary Component) bool

	// MatchConfidence returns a confidence score (0-100) for the match
	MatchConfidence(primary, secondary Component) int

	// Strategy returns the name of the matching strategy
	Strategy() string
}

// Component is a unified interface for both CDX and SPDX components
type Component interface {
	// Core identifiers
	GetPurl() string
	GetCPE() string
	GetName() string
	GetVersion() string
	GetType() string

	// Format detection
	IsCDX() bool
	IsSPDX() bool

	// Original component access
	GetOriginal() interface{}
}

// MatcherFactory creates the appropriate matcher based on strategy
type MatcherFactory interface {
	GetMatcher(strategy string) (ComponentMatcher, error)
}

// MatchResult contains the result of a component match operation
type MatchResult struct {
	Matched    bool
	Confidence int
	Strategy   string
	Primary    Component
	Secondary  Component
}

// MatchError represents an error during matching
type MatchError struct {
	Component Component
	Strategy  string
	Reason    string
}

func (e *MatchError) Error() string {
	return fmt.Sprintf("match error for strategy %s: %s", e.Strategy, e.Reason)
}

// MatcherConfig contains configuration for matchers
type MatcherConfig struct {
	Strategy      string
	StrictVersion bool
	FuzzyMatch    bool
	TypeMatch     bool
	MinConfidence int
}
