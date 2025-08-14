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

	"github.com/interlynk-io/sbomqs/pkg/sbom"
)

type Target struct {
	Component sbom.GetComponent
	Field     string
}

type Config struct {
	Fields   []string
	Output   string
	SBOMFile string
	Verbose  bool
	Force    bool
	Debug    bool
}

type Summary struct {
	Enriched int
	Skipped  int
	Failed   int
	Errors   []error
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

	return nil
}
