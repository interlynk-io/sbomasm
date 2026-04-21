// Copyright 2026 Interlynk.io
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

package gsbom

import (
	"fmt"
	"os"
	"strings"

	"github.com/interlynk-io/sbomasm/v2/pkg/generate/app"
	"go.yaml.in/yaml/v2"
)

var allowedPrimaryPurpose = map[string]bool{
	"application":      true,
	"framework":        true,
	"library":          true,
	"container":        true,
	"platform":         true,
	"firmware":         true,
	"operating-system": true,
	"device":           true,
	"file":             true,
}

var allowedLifecyclePhases = map[string]bool{
	"design":       true,
	"pre-build":    true,
	"build":        true,
	"post-build":   true,
	"operations":   true,
	"discovery":    true,
	"decommission": true,
}

// LoadArtifactConfig performs the following steps:
// 1. Read ".artifact-metadata.yaml" from current directory
// 2. Unmarshals the YAML data into an app.Config struct
// 3. Validates required fields and sanitizes optional fields
// 4. Maps the app.Config to an Artifact struct and returns it.
func LoadArtifactConfig(path string) (*Artifact, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("artifact metadata file not found: %s\nrun 'sbomasm generate config > %s'", path, path)
		}
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg app.Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse yaml: %w", err)
	}

	if err := validateAndSanitize(&cfg); err != nil {
		return nil, err
	}

	artifact := mapToArtifact(cfg)

	// Set default lifecycle if none provided
	if len(artifact.Lifecycles) == 0 {
		artifact.Lifecycles = []Lifecycle{{Phase: "build"}}
	}

	return artifact, nil
}

// validateAndSanitize performs the following:
// 1. Checks that required fields (Name, Version, PrimaryPurpose) are present.
// 2. Trims whitespace from all string fields.
// 3. Converts any field with value "[optional]" (case-insensitive) to an empty string.
func validateAndSanitize(cfg *app.Config) error {
	if cfg == nil {
		return fmt.Errorf("config is nil")
	}

	// --- sanitize helper ---
	sanitize := func(v string) string {
		vs := strings.TrimSpace(v)
		if strings.EqualFold(vs, "[optional]") {
			return ""
		}
		return v
	}

	validValue := func(v string) bool {
		vl := strings.TrimSpace(v)
		if vl == "" || strings.EqualFold(vl, "[required]") {
			return false
		}
		return true
	}

	// --- sanitize fields ---
	cfg.App.Name = sanitize(cfg.App.Name)
	cfg.App.Version = sanitize(cfg.App.Version)
	cfg.App.Description = sanitize(cfg.App.Description)
	cfg.App.PrimaryPurpose = sanitize(cfg.App.PrimaryPurpose)
	cfg.App.Purl = sanitize(cfg.App.Purl)
	cfg.App.CPE = sanitize(cfg.App.CPE)
	cfg.App.Copyright = sanitize(cfg.App.Copyright)
	cfg.App.Supplier.Name = sanitize(cfg.App.Supplier.Name)
	cfg.App.Supplier.Email = sanitize(cfg.App.Supplier.Email)
	cfg.App.License.Id = sanitize(cfg.App.License.Id)
	cfg.App.Supplier.URL = sanitize(cfg.App.Supplier.URL)

	for i := range cfg.App.Author {
		cfg.App.Author[i].Name = sanitize(cfg.App.Author[i].Name)
		cfg.App.Author[i].Email = sanitize(cfg.App.Author[i].Email)
	}

	for i := range cfg.App.ExternalRefs {
		cfg.App.ExternalRefs[i].Type = sanitize(cfg.App.ExternalRefs[i].Type)
		cfg.App.ExternalRefs[i].URL = sanitize(cfg.App.ExternalRefs[i].URL)
		cfg.App.ExternalRefs[i].Comment = sanitize(cfg.App.ExternalRefs[i].Comment)
	}

	for i := range cfg.App.Lifecycles {
		cfg.App.Lifecycles[i].Phase = sanitize(cfg.App.Lifecycles[i].Phase)
	}

	cfg.Output.Spec = sanitize(cfg.Output.Spec)
	cfg.Output.SpecVersion = sanitize(cfg.Output.SpecVersion)
	cfg.Output.FileFormat = sanitize(cfg.Output.FileFormat)

	// --- required validation ---
	if !validValue(cfg.App.Name) {
		return fmt.Errorf("artifact name is required")
	}
	if !validValue(cfg.App.Version) {
		return fmt.Errorf("artifact version is required")
	}
	if !validValue(cfg.App.PrimaryPurpose) {
		return fmt.Errorf("artifact primary_purpose is required")
	}

	if !allowedPrimaryPurpose[strings.ToLower(cfg.App.PrimaryPurpose)] {
		return fmt.Errorf("invalid primary_purpose: %s\nallowed values are: application, framework, library, container, platform, firmware, operating-system, device, file", cfg.App.PrimaryPurpose)
	}

	// Validate lifecycle phases
	for _, lc := range cfg.App.Lifecycles {
		phase := strings.ToLower(lc.Phase)
		if phase != "" && !allowedLifecyclePhases[phase] {
			return fmt.Errorf("invalid lifecycle phase: %s\nallowed values are: design, pre-build, build, post-build, operations, discovery, decommission", lc.Phase)
		}
	}

	return nil
}

// mapToArtifact converts an app.Config to an Artifact struct.
func mapToArtifact(cfg app.Config) *Artifact {
	return &Artifact{
		Name:           cfg.App.Name,
		Version:        cfg.App.Version,
		PrimaryPurpose: cfg.App.PrimaryPurpose,
		Description:    cfg.App.Description,

		Supplier: Supplier{
			Name:  cfg.App.Supplier.Name,
			Email: cfg.App.Supplier.Email,
			URL:   cfg.App.Supplier.URL,
		},

		Authors: func() []Author {
			authors := make([]Author, len(cfg.App.Author))
			for i, a := range cfg.App.Author {
				authors[i] = Author{
					Name:  a.Name,
					Email: a.Email,
				}
			}
			return authors
		}(),

		License:   cfg.App.License.Id,
		PURL:      cfg.App.Purl,
		CPE:       cfg.App.CPE,
		Copyright: cfg.App.Copyright,

		ExternalRefs: func() []ExternalRef {
			refs := make([]ExternalRef, len(cfg.App.ExternalRefs))
			for i, r := range cfg.App.ExternalRefs {
				refs[i] = ExternalRef{
					Type:    r.Type,
					URL:     r.URL,
					Comment: r.Comment,
				}
			}
			return refs
		}(),

		Lifecycles: func() []Lifecycle {
			lifecycles := make([]Lifecycle, len(cfg.App.Lifecycles))
			for i, l := range cfg.App.Lifecycles {
				lifecycles[i] = Lifecycle{
					Phase: l.Phase,
				}
			}
			return lifecycles
		}(),

		OutputConfig: OutputConfig{
			Spec:        cfg.Output.Spec,
			SpecVersion: cfg.Output.SpecVersion,
			FileFormat:  cfg.Output.FileFormat,
		},
	}
}
