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
	"github.com/interlynk-io/sbomasm/pkg/enrich/clearlydef"
	"github.com/interlynk-io/sbomasm/pkg/enrich/types"
	"github.com/interlynk-io/sbomqs/pkg/sbom"
)

func Enricher(sbom sbom.Document, targets []types.EnrichmentTarget, responses map[sbom.GetComponent]clearlydef.DefinitionResponse, force bool) sbom.Document {
	for _, target := range targets {
		componentIndex := findComponentIndex(sbom.Components(), target.Component)
		if componentIndex == -1 {
			continue
		}
		response, ok := responses[target.Component]
		if !ok || response.Licensed.Declared == "" {
			continue
		}
		if target.Field == "license" && (force || sbom.Components()[componentIndex].GetPackageLicenseConcluded() == "" || sbom.Components()[componentIndex].GetPackageLicenseConcluded() == "NOASSERTION") {
			// sbom.Components()[componentIndex].SetPackageLicenseConcluded(response.Licensed.Declared)
		}
	}
	return sbom
}

func findComponentIndex(components []sbom.GetComponent, comp sbom.GetComponent) int {
	for i, c := range components {
		if c.GetID() == comp.GetID() {
			return i
		}
	}
	return -1
}
