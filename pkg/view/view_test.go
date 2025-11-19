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
	"testing"
	"time"
)

func TestDefaultDisplayConfig(t *testing.T) {
	config := DefaultDisplayConfig()

	if !config.ShowDependencies {
		t.Error("Expected ShowDependencies to be true by default")
	}

	if !config.ShowVulnerabilities {
		t.Error("Expected ShowVulnerabilities to be true by default")
	}

	if config.Format != "tree" {
		t.Errorf("Expected default format to be 'tree', got '%s'", config.Format)
	}
}

func TestNewDisplayConfig(t *testing.T) {
	config := NewDisplayConfig(
		WithVerbose(true),
		WithMaxDepth(5),
		WithFormat("flat"),
	)

	if !config.VerboseOutput {
		t.Error("Expected VerboseOutput to be true")
	}

	if config.MaxDepth != 5 {
		t.Errorf("Expected MaxDepth to be 5, got %d", config.MaxDepth)
	}

	if config.Format != "flat" {
		t.Errorf("Expected format to be 'flat', got '%s'", config.Format)
	}
}

func TestValidateConfig(t *testing.T) {
	tests := []struct {
		name    string
		config  DisplayConfig
		wantErr bool
	}{
		{
			name:    "valid config",
			config:  DefaultDisplayConfig(),
			wantErr: false,
		},
		{
			name: "invalid format",
			config: DisplayConfig{
				Format: "invalid",
			},
			wantErr: true,
		},
		{
			name: "invalid severity",
			config: DisplayConfig{
				Format:      "tree",
				MinSeverity: "invalid",
			},
			wantErr: true,
		},
		{
			name: "negative max depth",
			config: DisplayConfig{
				Format:   "tree",
				MaxDepth: -1,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestParseTypeFilter(t *testing.T) {
	tests := []struct {
		name     string
		filter   string
		expected []string
	}{
		{
			name:     "empty filter",
			filter:   "",
			expected: nil,
		},
		{
			name:     "single type",
			filter:   "library",
			expected: []string{"library"},
		},
		{
			name:     "multiple types",
			filter:   "library,container,application",
			expected: []string{"library", "container", "application"},
		},
		{
			name:     "types with spaces",
			filter:   "library, container, application",
			expected: []string{"library", "container", "application"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParseTypeFilter(tt.filter)
			if len(result) != len(tt.expected) {
				t.Errorf("ParseTypeFilter() length = %d, want %d", len(result), len(tt.expected))
				return
			}
			for i, v := range result {
				if v != tt.expected[i] {
					t.Errorf("ParseTypeFilter()[%d] = %s, want %s", i, v, tt.expected[i])
				}
			}
		})
	}
}

func TestValidateSeverity(t *testing.T) {
	tests := []struct {
		severity string
		want     bool
	}{
		{"critical", true},
		{"high", true},
		{"medium", true},
		{"low", true},
		{"none", true},
		{"CRITICAL", true}, // case insensitive
		{"invalid", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.severity, func(t *testing.T) {
			if got := ValidateSeverity(tt.severity); got != tt.want {
				t.Errorf("ValidateSeverity(%s) = %v, want %v", tt.severity, got, tt.want)
			}
		})
	}
}

func TestAggregateVulnStats(t *testing.T) {
	vulns := []VulnerabilityInfo{
		{Severity: "critical"},
		{Severity: "high"},
		{Severity: "high"},
		{Severity: "medium"},
		{Severity: "low"},
		{Severity: "unknown"},
	}

	stats := aggregateVulnStats(vulns)

	if stats.Total != 6 {
		t.Errorf("Total = %d, want 6", stats.Total)
	}
	if stats.Critical != 1 {
		t.Errorf("Critical = %d, want 1", stats.Critical)
	}
	if stats.High != 2 {
		t.Errorf("High = %d, want 2", stats.High)
	}
	if stats.Medium != 1 {
		t.Errorf("Medium = %d, want 1", stats.Medium)
	}
	if stats.Low != 1 {
		t.Errorf("Low = %d, want 1", stats.Low)
	}
	if stats.Unknown != 1 {
		t.Errorf("Unknown = %d, want 1", stats.Unknown)
	}
}

func TestTruncateString(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		maxLen int
		want   string
	}{
		{
			name:   "short string",
			input:  "hello",
			maxLen: 10,
			want:   "hello",
		},
		{
			name:   "exact length",
			input:  "hello",
			maxLen: 5,
			want:   "hello",
		},
		{
			name:   "needs truncation",
			input:  "hello world",
			maxLen: 8,
			want:   "hello...",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := truncateString(tt.input, tt.maxLen); got != tt.want {
				t.Errorf("truncateString() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPluralize(t *testing.T) {
	tests := []struct {
		count    int
		singular string
		plural   string
		want     string
	}{
		{0, "component", "components", "0 components"},
		{1, "component", "components", "1 component"},
		{5, "component", "components", "5 components"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := Pluralize(tt.count, tt.singular, tt.plural); got != tt.want {
				t.Errorf("Pluralize() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMeetsSeverityThreshold(t *testing.T) {
	tests := []struct {
		name      string
		severity  string
		threshold string
		want      bool
	}{
		{"critical meets critical", "critical", "critical", true},
		{"critical meets high", "critical", "high", true},
		{"high meets high", "high", "high", true},
		{"high does not meet critical", "high", "critical", false},
		{"medium meets low", "medium", "low", true},
		{"low does not meet medium", "low", "medium", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := meetsSeverityThreshold(tt.severity, tt.threshold); got != tt.want {
				t.Errorf("meetsSeverityThreshold(%s, %s) = %v, want %v",
					tt.severity, tt.threshold, got, tt.want)
			}
		})
	}
}

func TestLoadSBOM(t *testing.T) {
	// Test with non-existent file
	_, err := LoadSBOM("nonexistent.json")
	if err == nil {
		t.Error("Expected error for non-existent file")
	}

	// Test with invalid JSON would require a test fixture
	// Skipping for now as this is a basic test suite
}

func TestCalculateDepth(t *testing.T) {
	// Create a simple component hierarchy
	root := &EnrichedComponent{
		Name: "root",
	}

	child1 := &EnrichedComponent{
		Name:   "child1",
		Parent: root,
	}

	child2 := &EnrichedComponent{
		Name:   "child2",
		Parent: child1,
	}

	tests := []struct {
		name string
		comp *EnrichedComponent
		want int
	}{
		{"root component", root, 0},
		{"first level", child1, 1},
		{"second level", child2, 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := calculateDepth(tt.comp); got != tt.want {
				t.Errorf("calculateDepth() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsUnresolved(t *testing.T) {
	tests := []struct {
		state string
		want  bool
	}{
		{"false_positive", false},
		{"not_affected", false},
		{"resolved", false},
		{"resolved_with_patchable_fix", false},
		{"exploitable", true},
		{"in_triage", true},
		{"", true},
	}

	for _, tt := range tests {
		t.Run(tt.state, func(t *testing.T) {
			if got := isUnresolved(tt.state); got != tt.want {
				t.Errorf("isUnresolved(%s) = %v, want %v", tt.state, got, tt.want)
			}
		})
	}
}

func TestFormatters(t *testing.T) {
	scheme := NoColorScheme()

	t.Run("FormatPURL", func(t *testing.T) {
		purl := "pkg:apk/alpine/gnutls@3.8.8-r0"
		result := FormatPURL(purl, scheme)
		if !strings.Contains(result, purl) {
			t.Errorf("FormatPURL should contain the purl")
		}
	})

	t.Run("FormatCPE", func(t *testing.T) {
		cpe := "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"
		result := FormatCPE(cpe, scheme)
		if !strings.Contains(result, cpe) {
			t.Errorf("FormatCPE should contain the cpe")
		}
	})

	t.Run("FormatVulnerabilitySummary", func(t *testing.T) {
		stats := VulnerabilityStats{
			Total:    5,
			Critical: 1,
			High:     2,
			Medium:   1,
			Low:      1,
		}
		result := FormatVulnerabilitySummary(stats, scheme)
		if !strings.Contains(result, "5") {
			t.Errorf("FormatVulnerabilitySummary should contain total count")
		}
	})
}

func TestFormatRelativeTime(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name     string
		time     time.Time
		expected string
	}{
		{
			name:     "just now",
			time:     now.Add(-30 * time.Second),
			expected: "just now",
		},
		{
			name:     "5 minutes ago",
			time:     now.Add(-5 * time.Minute),
			expected: "5 minutes ago",
		},
		{
			name:     "1 hour ago",
			time:     now.Add(-1 * time.Hour),
			expected: "1 hour ago",
		},
		{
			name:     "5 days ago",
			time:     now.Add(-5 * 24 * time.Hour),
			expected: "5 days ago",
		},
		{
			name:     "1 month ago",
			time:     now.Add(-35 * 24 * time.Hour),
			expected: "1 month ago",
		},
		{
			name:     "1 year ago",
			time:     now.Add(-400 * 24 * time.Hour),
			expected: "1 year ago",
		},
		{
			name:     "future time",
			time:     now.Add(4*24*time.Hour + 12*time.Hour), // 4-5 days
			expected: "4 days from now",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatRelativeTime(tt.time)
			if result != tt.expected {
				t.Errorf("formatRelativeTime() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestFormatDuration(t *testing.T) {
	tests := []struct {
		name     string
		duration time.Duration
		expected string
	}{
		{"seconds", 30 * time.Second, "just now"},
		{"1 minute", 1 * time.Minute, "1 minute"},
		{"5 minutes", 5 * time.Minute, "5 minutes"},
		{"1 hour", 1 * time.Hour, "1 hour"},
		{"3 hours", 3 * time.Hour, "3 hours"},
		{"1 day", 24 * time.Hour, "1 day"},
		{"7 days", 7 * 24 * time.Hour, "7 days"},
		{"1 month", 35 * 24 * time.Hour, "1 month"},
		{"3 months", 100 * 24 * time.Hour, "3 months"},
		{"1 year", 400 * 24 * time.Hour, "1 year"},
		{"2 years", 800 * 24 * time.Hour, "2 years"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatDuration(tt.duration)
			if result != tt.expected {
				t.Errorf("formatDuration() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestIslandDetection(t *testing.T) {
	// Create a test graph with primary component and some disconnected components
	graph := &ComponentGraph{
		AllNodes: make(map[string]*EnrichedComponent),
		DepGraph: make(map[string][]string),
	}

	// Primary component
	primary := &EnrichedComponent{
		BOMRef: "primary",
		Name:   "Primary",
	}
	graph.Primary = primary
	graph.AllNodes["primary"] = primary

	// Component connected to primary
	connected := &EnrichedComponent{
		BOMRef: "connected",
		Name:   "Connected",
	}
	graph.AllNodes["connected"] = connected
	graph.DepGraph["primary"] = []string{"connected"}

	// Island components (not reachable from primary)
	island1 := &EnrichedComponent{
		BOMRef: "island1",
		Name:   "Island1",
	}
	island2 := &EnrichedComponent{
		BOMRef: "island2",
		Name:   "Island2",
	}
	graph.AllNodes["island1"] = island1
	graph.AllNodes["island2"] = island2

	// Island components connected to each other
	graph.DepGraph["island1"] = []string{"island2"}

	// Build graph and detect islands
	BuildGraph(graph)

	// Verify islands were detected
	if len(graph.Islands) != 1 {
		t.Errorf("Expected 1 island, got %d", len(graph.Islands))
	}

	// Verify island contains both disconnected components
	if len(graph.Islands) > 0 {
		islandSize := len(graph.Islands[0])
		if islandSize != 2 {
			t.Errorf("Expected island to have 2 components, got %d", islandSize)
		}

		// Verify island IDs are set
		if island1.IslandID == 0 {
			t.Error("Island1 should have IslandID set")
		}
		if island2.IslandID == 0 {
			t.Error("Island2 should have IslandID set")
		}
		if island1.IslandID != island2.IslandID {
			t.Error("Island1 and Island2 should have the same IslandID")
		}
	}

	// Verify connected component is NOT in an island
	if connected.IslandID != 0 {
		t.Error("Connected component should not be in an island")
	}
}

func TestNoIslandsWhenAllConnected(t *testing.T) {
	// Create a graph where all components are reachable from primary
	graph := &ComponentGraph{
		AllNodes: make(map[string]*EnrichedComponent),
		DepGraph: make(map[string][]string),
	}

	// Primary component
	primary := &EnrichedComponent{
		BOMRef: "primary",
		Name:   "Primary",
	}
	graph.Primary = primary
	graph.AllNodes["primary"] = primary

	// All components connected through dependency chain
	comp1 := &EnrichedComponent{BOMRef: "comp1", Name: "Comp1"}
	comp2 := &EnrichedComponent{BOMRef: "comp2", Name: "Comp2"}
	comp3 := &EnrichedComponent{BOMRef: "comp3", Name: "Comp3"}

	graph.AllNodes["comp1"] = comp1
	graph.AllNodes["comp2"] = comp2
	graph.AllNodes["comp3"] = comp3

	graph.DepGraph["primary"] = []string{"comp1"}
	graph.DepGraph["comp1"] = []string{"comp2"}
	graph.DepGraph["comp2"] = []string{"comp3"}

	// Build graph and detect islands
	BuildGraph(graph)

	// Verify no islands
	if len(graph.Islands) != 0 {
		t.Errorf("Expected no islands, got %d", len(graph.Islands))
	}

	// Verify no component has island ID
	for _, comp := range graph.AllNodes {
		if comp.IslandID != 0 {
			t.Errorf("Component %s should not have IslandID set", comp.Name)
		}
	}
}
