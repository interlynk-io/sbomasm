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

package enrich

import (
	"fmt"
	"strings"
	"time"

	"github.com/interlynk-io/sbomqs/pkg/sbom"
)

var supportedLicenseExpressions = map[string]bool{
	"OR":   true,
	"AND":  true,
	"WITH": true,
	"+":    true,
}

type Target struct {
	Component sbom.GetComponent
	Field     string
}

type Config struct {
	Fields                  []string
	Output                  string
	SBOMFile                string
	Force                   bool
	Debug                   bool
	MaxRetries              int
	MaxWait                 time.Duration
	LicenseExpressionJoinBy string
	ChunkSize               int
}

type EnrichSummary struct {
	TotalComponents    int
	SelectedComponents int
	Enriched           int
	Skipped            int
	Failed             int
	Errors             []error
	SkippedReasons     map[string]string
}

func NewEnrichSummary() *EnrichSummary {
	return &EnrichSummary{
		TotalComponents:    0,
		SelectedComponents: 0,
		Enriched:           0,
		Skipped:            0,
		SkippedReasons:     make(map[string]string),
		Failed:             0,
		Errors:             nil,
	}
}

// SupportedEnrichFields defines the valid fields for enrichment.
var SupportedEnrichFields = map[string]bool{
	"license": true,
	// Add future supported fields here, e.g.,
	// "supplier": true,
	// "downloadLocation": true
}

func (p *Config) Validate() error {
	if len(p.Fields) == 0 {
		return fmt.Errorf("no fields specified for enrichment")
	}

	for _, field := range p.Fields {
		if !SupportedEnrichFields[strings.ToLower(field)] {
			return fmt.Errorf("unsupported field: %s (supported: %v)", field, SupportedEnrichFields)
		}
	}

	if !supportedLicenseExpressions[p.LicenseExpressionJoinBy] {
		return fmt.Errorf("unsupported license expression: %s (only supports: %v)", p.LicenseExpressionJoinBy, supportedLicenseExpressions)
	}

	return nil
}
