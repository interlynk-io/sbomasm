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

package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/interlynk-io/sbomasm/pkg/view"
	"github.com/spf13/cobra"
)

var viewCmd = &cobra.Command{
	Use:   "view <sbom-file>",
	Short: "View SBOM in a human-readable tree format",
	Long: `View displays CycloneDX SBOMs in a unified, hierarchical tree format.

The viewer consolidates information from various SBOM sections (components,
dependencies, vulnerabilities, compositions, annotations) into an intuitive
tree-based view that makes it easy to understand component relationships
and security posture.

Examples:
  # Basic view with defaults
  sbomasm view samples/product.json

  # Detailed view with all information
  sbomasm view samples/product.json --verbose

  # Focus on vulnerabilities
  sbomasm view samples/product.json -v --min-severity high --only-unresolved

  # Compact view for large SBOMs
  sbomasm view samples/artemis.json --max-depth 3 --hide-islands

  # View specific component types
  sbomasm view samples/foo.json --filter-type "library,container"

  # JSON output for processing
  sbomasm view samples/product.json --format json -o enriched.json`,
	Args: cobra.ExactArgs(1),
	RunE: runView,
}

var (
	// Detail level flags
	viewVerbose      bool
	viewDependencies bool
	viewVulns        bool
	viewAnnotations  bool
	viewCompositions bool
	viewProperties   bool
	viewHashes       bool
	viewLicenses     bool
	viewOnlyLicenses bool

	// Filtering flags
	viewMaxDepth    int
	viewFilterType  string
	viewHideIslands bool
	viewOnlyPrimary bool

	// Vulnerability filtering
	viewMinSeverity    string
	viewOnlyUnresolved bool

	// Output flags
	viewFormat  string
	viewOutput  string
	viewNoColor bool
	viewQuiet   bool
)

func init() {
	rootCmd.AddCommand(viewCmd)

	// Detail level flags
	viewCmd.Flags().BoolVarP(&viewVerbose, "verbose", "V", false, "Show all available fields")
	viewCmd.Flags().BoolVar(&viewDependencies, "dependencies", true, "Show dependencies section")
	viewCmd.Flags().BoolVarP(&viewVulns, "vulnerabilities", "v", true, "Show vulnerabilities section")
	viewCmd.Flags().BoolVarP(&viewAnnotations, "annotations", "a", true, "Show annotations section")
	viewCmd.Flags().BoolVarP(&viewCompositions, "compositions", "c", false, "Show compositions section")
	viewCmd.Flags().BoolVarP(&viewProperties, "properties", "p", false, "Show custom properties")
	viewCmd.Flags().BoolVar(&viewHashes, "hashes", false, "Show component hashes")
	viewCmd.Flags().BoolVarP(&viewLicenses, "licenses", "l", false, "Show license information")
	viewCmd.Flags().BoolVar(&viewOnlyLicenses, "only-licenses", false, "Show only license information (minimal component details)")

	// Filtering flags
	viewCmd.Flags().IntVar(&viewMaxDepth, "max-depth", 0, "Maximum tree depth to display (0 = unlimited)")
	viewCmd.Flags().StringVar(&viewFilterType, "filter-type", "", "Filter by component type (comma-separated)")
	viewCmd.Flags().BoolVar(&viewHideIslands, "hide-islands", false, "Don't show disconnected components")
	viewCmd.Flags().BoolVar(&viewOnlyPrimary, "only-primary", false, "Only show primary component tree")

	// Vulnerability filtering
	viewCmd.Flags().StringVar(&viewMinSeverity, "min-severity", "", "Minimum vulnerability severity (low|medium|high|critical)")
	viewCmd.Flags().BoolVar(&viewOnlyUnresolved, "only-unresolved", false, "Only show unresolved vulnerabilities")

	// Output flags
	viewCmd.Flags().StringVar(&viewFormat, "format", "tree", "Output format: tree, flat, json")
	viewCmd.Flags().StringVarP(&viewOutput, "output", "o", "", "Write output to file instead of stdout")
	viewCmd.Flags().BoolVar(&viewNoColor, "no-color", false, "Disable colored output")
	viewCmd.Flags().BoolVarP(&viewQuiet, "quiet", "q", false, "Suppress all warnings")
}

func runView(cmd *cobra.Command, args []string) error {
	sbomPath := args[0]

	// Build display config
	config := buildDisplayConfig()

	// Validate config
	if err := config.Validate(); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	// Auto-configure color support if not explicitly disabled
	if !viewNoColor {
		view.AutoConfigureColor(&config)
	}

	// Load and parse SBOM
	graph, err := view.LoadSBOM(sbomPath)
	if err != nil {
		return fmt.Errorf("failed to load SBOM: %w", err)
	}

	// Build graph (link dependencies, detect islands)
	if err := view.BuildGraph(graph); err != nil {
		return fmt.Errorf("failed to build graph: %w", err)
	}

	// Apply filters if configured
	if viewFilterType != "" || viewMinSeverity != "" || viewOnlyUnresolved {
		filterConfig := view.FilterConfig{
			Types:          view.ParseTypeFilter(viewFilterType),
			MinSeverity:    viewMinSeverity,
			OnlyUnresolved: viewOnlyUnresolved,
			MaxDepth:       viewMaxDepth,
		}
		graph = view.ApplyFilters(graph, filterConfig)
	}

	// Validate graph
	if warnings := view.ValidateGraph(graph); len(warnings) > 0 && !viewQuiet {
		fmt.Fprintf(os.Stderr, "Warning: Graph validation found issues:\n")
		for _, warn := range warnings {
			fmt.Fprintf(os.Stderr, "  - %v\n", warn)
		}
	}

	// Determine output writer
	var output *os.File
	if viewOutput != "" {
		f, err := os.Create(viewOutput)
		if err != nil {
			return fmt.Errorf("failed to create output file: %w", err)
		}
		defer f.Close()
		output = f
	} else {
		output = os.Stdout
	}

	// Render based on format
	switch config.Format {
	case "tree":
		renderer := view.NewTreeRenderer(config)
		if err := renderer.Render(graph, output); err != nil {
			return fmt.Errorf("failed to render tree: %w", err)
		}

	case "flat":
		renderer := view.NewFlatRenderer(config)
		if err := renderer.Render(graph, output); err != nil {
			return fmt.Errorf("failed to render flat list: %w", err)
		}

	case "json":
		// Convert to JSON-safe format (breaks circular references)
		jsonGraph := view.ToJSONComponentGraph(graph)
		encoder := json.NewEncoder(output)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(jsonGraph); err != nil {
			return fmt.Errorf("failed to encode JSON: %w", err)
		}

	default:
		return fmt.Errorf("unsupported format: %s", config.Format)
	}

	return nil
}

func buildDisplayConfig() view.DisplayConfig {
	// Start with defaults
	config := view.DefaultDisplayConfig()

	// Apply only-licenses mode first (overrides other flags)
	if viewOnlyLicenses {
		config.ShowOnlyLicenses = true
		config.ShowLicenses = true
		config.ShowDependencies = false
		config.ShowVulnerabilities = false
		config.ShowAnnotations = false
		config.ShowCompositions = false
		config.ShowProperties = false
		config.ShowHashes = false
	} else if viewVerbose {
		// Apply verbose (it sets multiple flags)
		config.VerboseOutput = true
		config.ShowDependencies = true
		config.ShowVulnerabilities = true
		config.ShowAnnotations = true
		config.ShowCompositions = true
		config.ShowProperties = true
		config.ShowHashes = true
		config.ShowLicenses = true
	} else {
		// Apply individual flags
		config.ShowDependencies = viewDependencies
		config.ShowVulnerabilities = viewVulns
		config.ShowAnnotations = viewAnnotations
		config.ShowCompositions = viewCompositions
		config.ShowProperties = viewProperties
		config.ShowHashes = viewHashes
		config.ShowLicenses = viewLicenses
	}

	// Display preferences
	config.MaxDepth = viewMaxDepth
	config.CollapseIslands = viewHideIslands
	config.FilterByType = viewFilterType
	config.OnlyPrimary = viewOnlyPrimary

	// Vulnerability filters
	config.MinSeverity = viewMinSeverity
	config.OnlyUnresolved = viewOnlyUnresolved

	// Output format
	config.Format = viewFormat
	config.NoColor = viewNoColor
	config.Output = viewOutput

	return config
}
