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
	"strings"
	"time"

	"github.com/fatih/color"
)

// ColorScheme defines colors for different elements
type ColorScheme struct {
	Primary       *color.Color
	ComponentName *color.Color
	FieldLabel    *color.Color
	Critical      *color.Color
	High          *color.Color
	Medium        *color.Color
	Low           *color.Color
	TreeStructure *color.Color
	Dependencies  *color.Color
	Annotations   *color.Color
	Islands       *color.Color
	Success       *color.Color
	Info          *color.Color
	PURL          *color.Color
	License       *color.Color
	Supplier      *color.Color
}

// DefaultColorScheme returns the default color scheme
func DefaultColorScheme() *ColorScheme {
	return &ColorScheme{
		Primary:       color.New(color.FgCyan, color.Bold),
		ComponentName: color.New(color.FgWhite, color.Bold),
		FieldLabel:    color.New(color.FgHiBlack),
		Critical:      color.New(color.FgRed, color.Bold),
		High:          color.New(color.FgHiRed),
		Medium:        color.New(color.FgYellow),
		Low:           color.New(color.FgBlue),
		TreeStructure: color.New(color.FgHiBlack),
		Dependencies:  color.New(color.FgGreen),
		Annotations:   color.New(color.FgMagenta),
		Islands:       color.New(color.FgRed),
		Success:       color.New(color.FgGreen),
		Info:          color.New(color.FgCyan),
		PURL:          color.New(color.FgHiCyan),
		License:       color.New(color.FgHiYellow),
		Supplier:      color.New(color.FgHiMagenta),
	}
}

// NoColorScheme returns a scheme with no colors
func NoColorScheme() *ColorScheme {
	noColor := color.New()
	return &ColorScheme{
		Primary:       noColor,
		ComponentName: noColor,
		FieldLabel:    noColor,
		Critical:      noColor,
		High:          noColor,
		Medium:        noColor,
		Low:           noColor,
		TreeStructure: noColor,
		Dependencies:  noColor,
		Annotations:   noColor,
		Islands:       noColor,
		Success:       noColor,
		Info:          noColor,
		PURL:          noColor,
		License:       noColor,
		Supplier:      noColor,
	}
}

// FormatComponentHeader formats a component header line
func FormatComponentHeader(comp *EnrichedComponent, scheme *ColorScheme) string {
	var parts []string

	// Name and version
	nameVersion := comp.Name
	if comp.Version != "" {
		nameVersion += "@" + comp.Version
	}

	if comp.IsPrimary {
		parts = append(parts, scheme.Primary.Sprintf("%s [PRIMARY]", nameVersion))
	} else {
		parts = append(parts, scheme.ComponentName.Sprint(nameVersion))
	}

	// Type
	if comp.Type != "" {
		parts = append(parts, scheme.FieldLabel.Sprintf("(%s)", comp.Type))
	}

	return strings.Join(parts, " ")
}

// FormatVulnerabilitySummary formats a vulnerability summary
func FormatVulnerabilitySummary(stats VulnerabilityStats, scheme *ColorScheme) string {
	if stats.Total == 0 {
		return scheme.Success.Sprint("No embedded vulnerabilities")
	}

	var parts []string

	if stats.Critical > 0 {
		parts = append(parts, scheme.Critical.Sprintf("%dC", stats.Critical))
	}
	if stats.High > 0 {
		parts = append(parts, scheme.High.Sprintf("%dH", stats.High))
	}
	if stats.Medium > 0 {
		parts = append(parts, scheme.Medium.Sprintf("%dM", stats.Medium))
	}
	if stats.Low > 0 {
		parts = append(parts, scheme.Low.Sprintf("%dL", stats.Low))
	}
	if stats.Unknown > 0 {
		parts = append(parts, scheme.FieldLabel.Sprintf("%dU", stats.Unknown))
	}

	return fmt.Sprintf("Vulnerabilities: %d (%s)", stats.Total, strings.Join(parts, ", "))
}

// FormatVulnerability formats a single vulnerability
func FormatVulnerability(vuln VulnerabilityInfo, scheme *ColorScheme) string {
	severity := strings.ToUpper(vuln.Severity)
	var severityColor *color.Color

	switch strings.ToLower(vuln.Severity) {
	case "critical":
		severityColor = scheme.Critical
	case "high":
		severityColor = scheme.High
	case "medium":
		severityColor = scheme.Medium
	case "low":
		severityColor = scheme.Low
	default:
		severityColor = scheme.FieldLabel
	}

	parts := []string{
		fmt.Sprintf("%s [%s]", vuln.ID, severityColor.Sprint(severity)),
	}

	if vuln.AnalysisState != "" {
		parts = append(parts, scheme.FieldLabel.Sprintf("(%s)", vuln.AnalysisState))
	}

	if vuln.Score > 0 {
		parts = append(parts, scheme.FieldLabel.Sprintf("Score: %.1f", vuln.Score))
	}

	if vuln.SourceName != "" {
		parts = append(parts, scheme.FieldLabel.Sprintf("Source: %s", vuln.SourceName))
	}

	return strings.Join(parts, " ")
}

// FormatVulnerabilityVerbose formats a vulnerability with all details in compact inline format
// Format: CVE-ID (state)(SEVERITY)(Source)(Score)
func FormatVulnerabilityVerbose(vuln VulnerabilityInfo, scheme *ColorScheme, prefix string) string {
	severity := strings.ToUpper(vuln.Severity)
	var severityColor *color.Color

	switch strings.ToLower(vuln.Severity) {
	case "critical":
		severityColor = scheme.Critical
	case "high":
		severityColor = scheme.High
	case "medium":
		severityColor = scheme.Medium
	case "low":
		severityColor = scheme.Low
	default:
		severityColor = scheme.FieldLabel
	}

	var parts []string

	// ID
	parts = append(parts, vuln.ID)

	// Analysis state (if present)
	if vuln.AnalysisState != "" {
		parts = append(parts, scheme.FieldLabel.Sprintf("(%s)", vuln.AnalysisState))
	}

	// Severity
	if vuln.Severity != "" {
		parts = append(parts, severityColor.Sprintf("(%s)", severity))
	}

	// Source
	if vuln.SourceName != "" {
		parts = append(parts, scheme.Info.Sprintf("(%s)", vuln.SourceName))
	}

	// Score
	if vuln.Score > 0 {
		parts = append(parts, scheme.Info.Sprintf("(%.1f)", vuln.Score))
	}

	return strings.Join(parts, " ")
}

// FormatDependency formats a dependency
func FormatDependency(dep DependencyInfo, scheme *ColorScheme) string {
	nameVersion := dep.Name
	if dep.Version != "" {
		nameVersion += "@" + dep.Version
	}

	parts := []string{scheme.Dependencies.Sprint(nameVersion)}

	if dep.Type != "" && dep.Type != "unknown" {
		parts = append(parts, scheme.FieldLabel.Sprintf("(%s)", dep.Type))
	}

	return strings.Join(parts, " ")
}

// FormatDependencyVerbose formats a dependency with all details inline
// Format: name@version (type)(purl)(license1,license2)(supplier)
func FormatDependencyVerbose(dep DependencyInfo, scheme *ColorScheme) string {
	nameVersion := dep.Name
	if dep.Version != "" {
		nameVersion += "@" + dep.Version
	}

	parts := []string{scheme.Dependencies.Sprint(nameVersion)}

	// Type
	if dep.Type != "" && dep.Type != "unknown" {
		parts = append(parts, scheme.FieldLabel.Sprintf("(%s)", dep.Type))
	}

	// PURL
	if dep.PURL != "" {
		parts = append(parts, scheme.PURL.Sprintf("(%s)", dep.PURL))
	}

	// Licenses
	if len(dep.Licenses) > 0 {
		licenseStrs := make([]string, 0, len(dep.Licenses))
		for _, lic := range dep.Licenses {
			if lic.ID != "" {
				licenseStrs = append(licenseStrs, lic.ID)
			} else if lic.Name != "" {
				licenseStrs = append(licenseStrs, lic.Name)
			} else if lic.Expression != "" {
				licenseStrs = append(licenseStrs, lic.Expression)
			}
		}
		if len(licenseStrs) > 0 {
			parts = append(parts, scheme.License.Sprintf("(%s)", strings.Join(licenseStrs, ",")))
		}
	}

	// Supplier
	if dep.Supplier != "" {
		parts = append(parts, scheme.Supplier.Sprintf("(%s)", dep.Supplier))
	}

	return strings.Join(parts, " ")
}

// FormatPURL formats a package URL
func FormatPURL(purl string, scheme *ColorScheme) string {
	if purl == "" {
		return scheme.FieldLabel.Sprint("(no PURL)")
	}
	return scheme.PURL.Sprint(purl)
}

// FormatCPE formats a CPE string
func FormatCPE(cpe string, scheme *ColorScheme) string {
	if cpe == "" {
		return scheme.FieldLabel.Sprint("(no CPE)")
	}
	return scheme.Info.Sprint(cpe)
}

// FormatLicense formats license information
func FormatLicense(lic LicenseInfo, scheme *ColorScheme) string {
	if lic.ID != "" {
		return scheme.License.Sprint(lic.ID)
	}
	if lic.Name != "" {
		return scheme.License.Sprint(lic.Name)
	}
	if lic.Expression != "" {
		return scheme.License.Sprint(lic.Expression)
	}
	return scheme.FieldLabel.Sprint("(unknown)")
}

// FormatHash formats a hash
func FormatHash(hash HashInfo, scheme *ColorScheme) string {
	return fmt.Sprintf("%s: %s",
		scheme.FieldLabel.Sprint(hash.Algorithm),
		scheme.Info.Sprint(truncateString(hash.Value, 16)))
}

// FormatHashVerbose formats a hash with the full value
func FormatHashVerbose(hash HashInfo, scheme *ColorScheme) string {
	return fmt.Sprintf("%s: %s",
		scheme.FieldLabel.Sprint(hash.Algorithm),
		scheme.Info.Sprint(hash.Value))
}

// FormatProperty formats a property
func FormatProperty(prop PropertyInfo, scheme *ColorScheme) string {
	return fmt.Sprintf("%s: %s",
		scheme.FieldLabel.Sprint(prop.Name),
		scheme.Info.Sprint(truncateString(prop.Value, 50)))
}

// TruncateString truncates a string to maxLen characters
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

// Pluralize returns singular or plural form based on count
func Pluralize(count int, singular, plural string) string {
	if count == 1 {
		return fmt.Sprintf("%d %s", count, singular)
	}
	return fmt.Sprintf("%d %s", count, plural)
}

// FormatCount formats a count with label
func FormatCount(count int, label string, scheme *ColorScheme) string {
	if count == 0 {
		return scheme.FieldLabel.Sprintf("No %ss", label)
	}
	return scheme.Info.Sprint(Pluralize(count, label, label+"s"))
}

// FormatFieldValue formats a field name and value
func FormatFieldValue(field, value string, scheme *ColorScheme) string {
	if value == "" {
		return ""
	}
	return fmt.Sprintf("%s: %s",
		scheme.FieldLabel.Sprint(field),
		scheme.Info.Sprint(value))
}

// FormatListHeader formats a section header
func FormatListHeader(title string, count int, scheme *ColorScheme) string {
	if count == 0 {
		return scheme.FieldLabel.Sprintf("%s: none", title)
	}
	return scheme.ComponentName.Sprintf("%s (%d):", title, count)
}

// FormatStatistics formats overall statistics
func FormatStatistics(stats Statistics, scheme *ColorScheme) string {
	var lines []string

	lines = append(lines, scheme.ComponentName.Sprint("Statistics:"))
	lines = append(lines, fmt.Sprintf("  Total Components: %s",
		scheme.Info.Sprint(stats.TotalComponents)))
	lines = append(lines, fmt.Sprintf("  Total Dependencies: %s",
		scheme.Info.Sprint(stats.TotalDependencies)))
	lines = append(lines, fmt.Sprintf("  Max Depth: %s",
		scheme.Info.Sprint(stats.MaxDepth)))

	// Annotations and Compositions
	if stats.TotalAnnotations > 0 {
		lines = append(lines, fmt.Sprintf("  Total Annotations: %s",
			scheme.Info.Sprint(stats.TotalAnnotations)))
	}
	if stats.TotalCompositions > 0 {
		lines = append(lines, fmt.Sprintf("  Total Compositions: %s",
			scheme.Info.Sprint(stats.TotalCompositions)))
	}

	// Vulnerability summary
	if stats.TotalVulnerabilities.Total > 0 {
		vulnSummary := FormatVulnerabilitySummary(stats.TotalVulnerabilities, scheme)
		lines = append(lines, fmt.Sprintf("  %s", vulnSummary))
	} else {
		lines = append(lines, fmt.Sprintf("  %s", "No embedded vulnerabilities"))
	}

	// Component types breakdown
	if len(stats.ComponentsByType) > 0 {
		lines = append(lines, "  Components by type:")
		for compType, count := range stats.ComponentsByType {
			lines = append(lines, fmt.Sprintf("    %s: %s",
				scheme.FieldLabel.Sprint(compType),
				scheme.Info.Sprint(count)))
		}
	}

	// Islands
	if stats.IslandCount > 0 {
		lines = append(lines, fmt.Sprintf("  Islands: %s",
			scheme.Islands.Sprint(stats.IslandCount)))
	}

	return strings.Join(lines, "\n")
}

// FormatSBOMHeader formats the SBOM header
func FormatSBOMHeader(metadata SBOMMetadata, scheme *ColorScheme) string {
	var lines []string

	// Title line
	title := fmt.Sprintf("SBOM: %s %s", metadata.Format, metadata.SpecVersion)
	lines = append(lines, scheme.Primary.Sprint(title))

	if metadata.Timestamp.Year() > 1 {
		relativeTime := formatRelativeTime(metadata.Timestamp)
		lines = append(lines, scheme.FieldLabel.Sprintf("Generated: %s (%s)",
			metadata.Timestamp.Format("2006-01-02 15:04:05"), relativeTime))
	}

	if metadata.SerialNumber != "" {
		lines = append(lines, scheme.FieldLabel.Sprintf("Serial: %s",
			truncateString(metadata.SerialNumber, 50)))
	}

	if len(metadata.Tools) > 0 {
		toolStrs := make([]string, 0, len(metadata.Tools))
		for _, tool := range metadata.Tools {
			toolStr := tool.Name
			if tool.Version != "" {
				toolStr += " " + tool.Version
			}
			toolStrs = append(toolStrs, toolStr)
		}
		lines = append(lines, scheme.FieldLabel.Sprintf("Tools: %s",
			strings.Join(toolStrs, ", ")))
	}

	return strings.Join(lines, "\n")
}

// FormatSBOMHeaderVerbose formats the SBOM header with all metadata in verbose mode
func FormatSBOMHeaderVerbose(metadata SBOMMetadata, scheme *ColorScheme) string {
	var lines []string

	// Title line
	title := fmt.Sprintf("SBOM: %s %s", metadata.Format, metadata.SpecVersion)
	lines = append(lines, scheme.Primary.Sprint(title))

	if metadata.Timestamp.Year() > 1 {
		relativeTime := formatRelativeTime(metadata.Timestamp)
		lines = append(lines, scheme.FieldLabel.Sprintf("Generated: %s (%s)",
			metadata.Timestamp.Format("2006-01-02 15:04:05"), relativeTime))
	}

	if metadata.SerialNumber != "" {
		lines = append(lines, scheme.FieldLabel.Sprintf("Serial: %s",
			truncateString(metadata.SerialNumber, 50)))
	}

	// Supplier
	if metadata.Supplier != "" {
		lines = append(lines, fmt.Sprintf("Supplier: %s", scheme.Supplier.Sprint(metadata.Supplier)))
	}

	// Authors
	if len(metadata.Authors) > 0 {
		lines = append(lines, fmt.Sprintf("Authors: %s", scheme.Info.Sprint(strings.Join(metadata.Authors, ", "))))
	}

	// Manufacturer (same as supplier in CycloneDX)
	if metadata.Manufacturer != "" {
		lines = append(lines, fmt.Sprintf("Manufacturer: %s", scheme.Supplier.Sprint(metadata.Manufacturer)))
	}

	// Tools
	if len(metadata.Tools) > 0 {
		toolStrs := make([]string, 0, len(metadata.Tools))
		for _, tool := range metadata.Tools {
			toolStr := tool.Name
			if tool.Version != "" {
				toolStr += " " + tool.Version
			}
			if tool.Vendor != "" {
				toolStr = tool.Vendor + "/" + toolStr
			}
			toolStrs = append(toolStrs, toolStr)
		}
		lines = append(lines, scheme.FieldLabel.Sprintf("Tools: %s",
			strings.Join(toolStrs, ", ")))
	}

	// Licenses
	if len(metadata.Licenses) > 0 {
		licenseStrs := make([]string, 0, len(metadata.Licenses))
		for _, lic := range metadata.Licenses {
			licenseStrs = append(licenseStrs, FormatLicense(lic, scheme))
		}
		lines = append(lines, fmt.Sprintf("Licenses: %s", strings.Join(licenseStrs, ", ")))
	}

	return strings.Join(lines, "\n")
}

// formatRelativeTime formats a timestamp as relative time (e.g., "5 days ago")
func formatRelativeTime(t time.Time) string {
	now := time.Now()
	duration := now.Sub(t)

	// Future times
	if duration < 0 {
		duration = -duration
		return formatDuration(duration) + " from now"
	}

	// Handle "just now" specially
	formatted := formatDuration(duration)
	if formatted == "just now" {
		return formatted
	}

	// Past times
	return formatted + " ago"
}

// formatDuration formats a duration in human-readable form
func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return "just now"
	}

	if d < time.Hour {
		minutes := int(d.Minutes())
		if minutes == 1 {
			return "1 minute"
		}
		return fmt.Sprintf("%d minutes", minutes)
	}

	if d < 24*time.Hour {
		hours := int(d.Hours())
		if hours == 1 {
			return "1 hour"
		}
		return fmt.Sprintf("%d hours", hours)
	}

	if d < 30*24*time.Hour {
		days := int(d.Hours() / 24)
		if days == 1 {
			return "1 day"
		}
		return fmt.Sprintf("%d days", days)
	}

	if d < 365*24*time.Hour {
		months := int(d.Hours() / (24 * 30))
		if months == 1 {
			return "1 month"
		}
		return fmt.Sprintf("%d months", months)
	}

	years := int(d.Hours() / (24 * 365))
	if years == 1 {
		return "1 year"
	}
	return fmt.Sprintf("%d years", years)
}

// TreeSymbols contains symbols for drawing tree structures
type TreeSymbols struct {
	Vertical   string
	Branch     string
	Last       string
	Horizontal string
}

// DefaultTreeSymbols returns Unicode box-drawing characters
func DefaultTreeSymbols() TreeSymbols {
	return TreeSymbols{
		Vertical:   "│",
		Branch:     "├─",
		Last:       "└─",
		Horizontal: "─",
	}
}

// ASCIITreeSymbols returns ASCII-only characters
func ASCIITreeSymbols() TreeSymbols {
	return TreeSymbols{
		Vertical:   "|",
		Branch:     "|-",
		Last:       "+-",
		Horizontal: "-",
	}
}
