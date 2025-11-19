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
	"strings"
)

// FilterConfig contains filter settings
type FilterConfig struct {
	Types          []string
	MinSeverity    string
	OnlyUnresolved bool
	MaxDepth       int
}

// ApplyFilters applies all configured filters to the graph
func ApplyFilters(graph *ComponentGraph, config FilterConfig) *ComponentGraph {
	if len(config.Types) == 0 && config.MinSeverity == "" && !config.OnlyUnresolved && config.MaxDepth == 0 {
		// No filters to apply
		return graph
	}

	filtered := &ComponentGraph{
		AllNodes: make(map[string]*EnrichedComponent),
		DepGraph: graph.DepGraph,
		Metadata: graph.Metadata,
	}

	// Filter components
	for bomRef, comp := range graph.AllNodes {
		if shouldIncludeComponent(comp, config) {
			filtered.AllNodes[bomRef] = comp
		}
	}

	// Rebuild graph structure
	if graph.Primary != nil && shouldIncludeComponent(graph.Primary, config) {
		filtered.Primary = graph.Primary
	}

	return filtered
}

// shouldIncludeComponent determines if a component should be included based on filters
func shouldIncludeComponent(comp *EnrichedComponent, config FilterConfig) bool {
	// Type filter
	if len(config.Types) > 0 {
		if !containsType(config.Types, comp.Type) {
			return false
		}
	}

	// Vulnerability filters
	if config.MinSeverity != "" || config.OnlyUnresolved {
		if !matchesVulnerabilityFilter(comp, config.MinSeverity, config.OnlyUnresolved) {
			return false
		}
	}

	return true
}

// containsType checks if a type is in the list
func containsType(types []string, compType string) bool {
	for _, t := range types {
		if strings.EqualFold(t, compType) {
			return true
		}
	}
	return false
}

// matchesVulnerabilityFilter checks if component matches vulnerability criteria
func matchesVulnerabilityFilter(comp *EnrichedComponent, minSeverity string, onlyUnresolved bool) bool {
	if len(comp.Vulnerabilities) == 0 {
		return false
	}

	for _, vuln := range comp.Vulnerabilities {
		// Check unresolved filter
		if onlyUnresolved {
			if !isUnresolved(vuln.AnalysisState) {
				continue
			}
		}

		// Check severity filter
		if minSeverity != "" {
			if meetsSeverityThreshold(vuln.Severity, minSeverity) {
				return true
			}
		} else {
			return true
		}
	}

	return false
}

// isUnresolved checks if a vulnerability is unresolved
func isUnresolved(state string) bool {
	state = strings.ToLower(state)
	// Resolved states
	resolved := []string{
		"false_positive",
		"not_affected",
		"resolved",
		"resolved_with_patchable_fix",
	}

	for _, r := range resolved {
		if state == r {
			return false
		}
	}

	return true
}

// meetsSeverityThreshold checks if severity meets or exceeds threshold
func meetsSeverityThreshold(severity, threshold string) bool {
	severityLevels := map[string]int{
		"critical": 4,
		"high":     3,
		"medium":   2,
		"low":      1,
		"none":     0,
	}

	severityLevel := severityLevels[strings.ToLower(severity)]
	thresholdLevel := severityLevels[strings.ToLower(threshold)]

	return severityLevel >= thresholdLevel
}

// FilterVulnerabilities filters vulnerabilities based on criteria
func FilterVulnerabilities(vulns []VulnerabilityInfo, minSeverity string, onlyUnresolved bool) []VulnerabilityInfo {
	var filtered []VulnerabilityInfo

	for _, vuln := range vulns {
		if onlyUnresolved && !isUnresolved(vuln.AnalysisState) {
			continue
		}

		if minSeverity != "" && !meetsSeverityThreshold(vuln.Severity, minSeverity) {
			continue
		}

		filtered = append(filtered, vuln)
	}

	return filtered
}

// ParseTypeFilter parses a comma-separated type filter string
func ParseTypeFilter(filter string) []string {
	if filter == "" {
		return nil
	}

	parts := strings.Split(filter, ",")
	var types []string

	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			types = append(types, trimmed)
		}
	}

	return types
}

// ValidateSeverity validates a severity level
func ValidateSeverity(severity string) bool {
	validSeverities := []string{"critical", "high", "medium", "low", "none"}
	severity = strings.ToLower(severity)

	for _, valid := range validSeverities {
		if severity == valid {
			return true
		}
	}

	return false
}
