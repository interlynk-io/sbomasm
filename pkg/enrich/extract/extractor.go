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

package extract

import (
	"github.com/interlynk-io/sbomasm/pkg/enrich/types"
	"github.com/interlynk-io/sbomqs/pkg/sbom"
)

// type EnrichmentTarget struct {
// 	Component sbom.GetComponent
// 	Field     string
// }

// extract all the components with missing or NOASSERTION licenses
func Extractor(sbom sbom.Document, fields []string, force bool) []types.EnrichmentTarget {
	targets := []types.EnrichmentTarget{}
	for _, comp := range sbom.Components() {
		for _, field := range fields {
			if field == "license" {
				if force || comp.GetPackageLicenseConcluded() == "" || comp.GetPackageLicenseConcluded() == "NOASSERTION" {
					targets = append(targets, types.EnrichmentTarget{Component: comp, Field: field})
				}
			}
			// Future: Add for supplier, downloadLocation
		}
	}
	return targets
}
