// Copyright 2026 Interlynk.io
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package gsbom

import (
	"fmt"
	"strings"
)

// Allowed component types (matches schema enum)
var allowedComponentTypes = map[string]bool{
	"library":                true,
	"application":            true,
	"framework":              true,
	"container":              true,
	"operating-system":       true,
	"device":                 true,
	"firmware":               true,
	"file":                   true,
	"platform":               true,
	"device-driver":          true,
	"machine-learning-model": true,
	"data":                   true,
}

// ValidateComponent performs validation on a component after parsing.
// Returns an error if the component is invalid.
func ValidateComponent(c Component, index int, filePath string) error {
	// Required fields validation
	if strings.TrimSpace(c.Name) == "" {
		return fmt.Errorf("component[%d]: name is required (file: %s)", index, filePath)
	}

	if strings.TrimSpace(c.Version) == "" {
		return fmt.Errorf("component[%d]: version is required (file: %s)", index, filePath)
	}

	// Type validation (if provided)
	if c.Type != "" && !allowedComponentTypes[c.Type] {
		return fmt.Errorf("component[%d] %s@%s: invalid type '%s' (file: %s)\nallowed values: library, application, framework, container, operating-system, device, firmware, file, platform, device-driver, machine-learning-model, data",
			index, c.Name, c.Version, c.Type, filePath)
	}

	return nil
}

// SanitizeAndValidateComponents sanitizes all components and validates required fields.
// Returns an error if any component fails validation.
func SanitizeAndValidateComponents(components []Component, filePath string) ([]Component, error) {
	var validComponents []Component

	for i := range components {
		// Sanitize string fields
		sanitizeComponent(&components[i])

		// Validate component
		if err := ValidateComponent(components[i], i, filePath); err != nil {
			return nil, err
		}

		validComponents = append(validComponents, components[i])
	}

	return validComponents, nil
}

// sanitizeComponent trims whitespace from all string fields in a component.
func sanitizeComponent(c *Component) {
	c.Name = strings.TrimSpace(c.Name)
	c.Version = strings.TrimSpace(c.Version)
	c.Type = strings.TrimSpace(c.Type)
	c.Description = strings.TrimSpace(c.Description)
	c.PURL = strings.TrimSpace(c.PURL)
	c.CPE = strings.TrimSpace(c.CPE)
	c.Scope = strings.TrimSpace(c.Scope)

	// Sanitize supplier fields
	c.Supplier.Name = strings.TrimSpace(c.Supplier.Name)
	c.Supplier.Email = strings.TrimSpace(c.Supplier.Email)
	c.Supplier.URL = strings.TrimSpace(c.Supplier.URL)

	// Sanitize license expression if set
	if c.License.Expression != "" {
		c.License.Expression = strings.TrimSpace(c.License.Expression)
	}
	if c.License.ID != "" {
		c.License.ID = strings.TrimSpace(c.License.ID)
	}

	// Sanitize external refs
	for i := range c.ExternalRefs {
		c.ExternalRefs[i].Type = strings.TrimSpace(c.ExternalRefs[i].Type)
		c.ExternalRefs[i].URL = strings.TrimSpace(c.ExternalRefs[i].URL)
		c.ExternalRefs[i].Comment = strings.TrimSpace(c.ExternalRefs[i].Comment)
	}

	// Sanitize tags
	for i := range c.Tags {
		c.Tags[i] = strings.TrimSpace(c.Tags[i])
	}

	// Sanitize depends-on
	for i := range c.DependsOn {
		c.DependsOn[i] = strings.TrimSpace(c.DependsOn[i])
	}
}
