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

// DefaultMatcherFactory is the default implementation of MatcherFactory
type DefaultMatcherFactory struct {
	config *MatcherConfig
}

// NewDefaultMatcherFactory creates a new DefaultMatcherFactory
func NewDefaultMatcherFactory(config *MatcherConfig) MatcherFactory {
	if config == nil {
		config = &MatcherConfig{
			Strategy:      "purl",
			StrictVersion: false,
			FuzzyMatch:    false,
			TypeMatch:     true,
		}
	}
	return &DefaultMatcherFactory{
		config: config,
	}
}

// GetMatcher returns a ComponentMatcher based on the strategy
func (f *DefaultMatcherFactory) GetMatcher(strategy string) (ComponentMatcher, error) {
	switch strategy {
	case "purl":
		return NewPurlMatcher(!f.config.StrictVersion), nil
	case "cpe":
		return NewCPEMatcher(!f.config.StrictVersion), nil
	case "name-version":
		return NewNameVersionMatcher(f.config.FuzzyMatch, f.config.TypeMatch), nil
	default:
		return nil, fmt.Errorf("unknown matching strategy: %s", strategy)
	}
}

// GetMatcherWithConfig returns a ComponentMatcher with specific configuration
func GetMatcherWithConfig(config *MatcherConfig) (ComponentMatcher, error) {
	factory := NewDefaultMatcherFactory(config)
	return factory.GetMatcher(config.Strategy)
}