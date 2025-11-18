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

package view

import (
	"fmt"
	"os"
)

// ConfigOption is a functional option for configuring DisplayConfig
type ConfigOption func(*DisplayConfig)

// WithVerbose enables verbose output
func WithVerbose(verbose bool) ConfigOption {
	return func(c *DisplayConfig) {
		c.VerboseOutput = verbose
		if verbose {
			c.ShowDependencies = true
			c.ShowVulnerabilities = true
			c.ShowAnnotations = true
			c.ShowCompositions = true
			c.ShowProperties = true
			c.ShowHashes = true
			c.ShowLicenses = true
		}
	}
}

// WithDependencies controls dependency display
func WithDependencies(show bool) ConfigOption {
	return func(c *DisplayConfig) {
		c.ShowDependencies = show
	}
}

// WithVulnerabilities controls vulnerability display
func WithVulnerabilities(show bool) ConfigOption {
	return func(c *DisplayConfig) {
		c.ShowVulnerabilities = show
	}
}

// WithAnnotations controls annotation display
func WithAnnotations(show bool) ConfigOption {
	return func(c *DisplayConfig) {
		c.ShowAnnotations = show
	}
}

// WithCompositions controls composition display
func WithCompositions(show bool) ConfigOption {
	return func(c *DisplayConfig) {
		c.ShowCompositions = show
	}
}

// WithProperties controls property display
func WithProperties(show bool) ConfigOption {
	return func(c *DisplayConfig) {
		c.ShowProperties = show
	}
}

// WithHashes controls hash display
func WithHashes(show bool) ConfigOption {
	return func(c *DisplayConfig) {
		c.ShowHashes = show
	}
}

// WithLicenses controls license display
func WithLicenses(show bool) ConfigOption {
	return func(c *DisplayConfig) {
		c.ShowLicenses = show
	}
}

// WithMaxDepth sets the maximum tree depth
func WithMaxDepth(depth int) ConfigOption {
	return func(c *DisplayConfig) {
		c.MaxDepth = depth
	}
}

// WithCollapseIslands controls island display
func WithCollapseIslands(collapse bool) ConfigOption {
	return func(c *DisplayConfig) {
		c.CollapseIslands = collapse
	}
}

// WithTypeFilter sets component type filter
func WithTypeFilter(filter string) ConfigOption {
	return func(c *DisplayConfig) {
		c.FilterByType = filter
	}
}

// WithOnlyPrimary shows only primary component tree
func WithOnlyPrimary(only bool) ConfigOption {
	return func(c *DisplayConfig) {
		c.OnlyPrimary = only
	}
}

// WithMinSeverity sets minimum vulnerability severity
func WithMinSeverity(severity string) ConfigOption {
	return func(c *DisplayConfig) {
		c.MinSeverity = severity
	}
}

// WithOnlyUnresolved shows only unresolved vulnerabilities
func WithOnlyUnresolved(only bool) ConfigOption {
	return func(c *DisplayConfig) {
		c.OnlyUnresolved = only
	}
}

// WithFormat sets output format
func WithFormat(format string) ConfigOption {
	return func(c *DisplayConfig) {
		c.Format = format
	}
}

// WithNoColor disables colored output
func WithNoColor(noColor bool) ConfigOption {
	return func(c *DisplayConfig) {
		c.NoColor = noColor
	}
}

// WithOutput sets output file
func WithOutput(output string) ConfigOption {
	return func(c *DisplayConfig) {
		c.Output = output
	}
}

// NewDisplayConfig creates a DisplayConfig with options
func NewDisplayConfig(options ...ConfigOption) DisplayConfig {
	config := DefaultDisplayConfig()

	for _, option := range options {
		option(&config)
	}

	return config
}

// Validate validates the configuration
func (c *DisplayConfig) Validate() error {
	// Validate format
	validFormats := []string{"tree", "flat", "json"}
	validFormat := false
	for _, f := range validFormats {
		if c.Format == f {
			validFormat = true
			break
		}
	}
	if !validFormat {
		return fmt.Errorf("invalid format: %s (valid: tree, flat, json)", c.Format)
	}

	// Validate severity
	if c.MinSeverity != "" && !ValidateSeverity(c.MinSeverity) {
		return fmt.Errorf("invalid severity: %s (valid: critical, high, medium, low, none)", c.MinSeverity)
	}

	// Validate max depth
	if c.MaxDepth < 0 {
		return fmt.Errorf("max depth must be >= 0")
	}

	return nil
}

// MinimalConfig returns a minimal display config
func MinimalConfig() DisplayConfig {
	return DisplayConfig{
		ShowDependencies:    false,
		ShowVulnerabilities: true,
		ShowAnnotations:     false,
		ShowCompositions:    false,
		ShowProperties:      false,
		ShowHashes:          false,
		ShowLicenses:        false,
		MaxDepth:            2,
		CollapseIslands:     true,
		VerboseOutput:       false,
		Format:              "tree",
		NoColor:             false,
	}
}

// CompactConfig returns a compact display config
func CompactConfig() DisplayConfig {
	return DisplayConfig{
		ShowDependencies:    true,
		ShowVulnerabilities: true,
		ShowAnnotations:     false,
		ShowCompositions:    false,
		ShowProperties:      false,
		ShowHashes:          false,
		ShowLicenses:        false,
		MaxDepth:            3,
		CollapseIslands:     false,
		VerboseOutput:       false,
		Format:              "tree",
		NoColor:             false,
	}
}

// VerboseConfig returns a verbose display config
func VerboseConfig() DisplayConfig {
	return DisplayConfig{
		ShowDependencies:    true,
		ShowVulnerabilities: true,
		ShowAnnotations:     true,
		ShowCompositions:    true,
		ShowProperties:      true,
		ShowHashes:          true,
		ShowLicenses:        true,
		MaxDepth:            0,
		CollapseIslands:     false,
		VerboseOutput:       true,
		Format:              "tree",
		NoColor:             false,
	}
}

// DetectColorSupport detects if the terminal supports colors
func DetectColorSupport() bool {
	// Check if stdout is a terminal
	if fileInfo, _ := os.Stdout.Stat(); (fileInfo.Mode() & os.ModeCharDevice) == 0 {
		return false
	}

	// Check TERM environment variable
	term := os.Getenv("TERM")
	if term == "" || term == "dumb" {
		return false
	}

	// Check NO_COLOR environment variable
	if os.Getenv("NO_COLOR") != "" {
		return false
	}

	return true
}

// AutoConfigureColor automatically configures color support
func AutoConfigureColor(config *DisplayConfig) {
	if !DetectColorSupport() {
		config.NoColor = true
	}
}
