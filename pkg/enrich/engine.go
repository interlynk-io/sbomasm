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
	"context"
	"fmt"
	"os"

	"github.com/interlynk-io/sbomasm/pkg/enrich/clearlydef"
	"github.com/interlynk-io/sbomasm/pkg/enrich/extract"
	"github.com/interlynk-io/sbomasm/pkg/logger"
	"github.com/interlynk-io/sbomasm/pkg/sbom"
)

func Engine(ctx context.Context, params *Config) (*Summary, error) {
	// Initialize the enrich engine with the provided parameters

	log := logger.FromContext(ctx)
	log.Debugf("Starting Enrich Engine")

	// parse the SBOM document
	sbomDoc, err := sbom.Parser(ctx, params.SBOMFile)
	if err != nil {
		return nil, err
	}

	log.Debugf("parsed SBOM document successfully: %s", sbomDoc.SpecType())

	extractParams := &extract.Params{
		Fields:  params.Fields,
		Force:   params.Force,
		Verbose: params.Verbose,
	}

	components, err := extract.Components(ctx, sbomDoc, extractParams)
	if err != nil {
		return nil, err
	}
	log.Debugf("total extracted components: %d", len(components))

	coordinates := clearlydef.Mapper(ctx, components)
	responses := clearlydef.Client(ctx, coordinates)

	// // extract targets
	// targets := extract.Extractor(sbomDoc, params.Fields, params.Force)

	// coordinates := clearlydef.Mapper(ctx, spec, targets)
	// log.Debugf("coordinates: %+v", coordinates)

	// responses := clearlydef.Client(ctx, coordinates)

	sbomDoc = Enricher(ctx, sbomDoc, components, responses, params.Force)

	newFile, err := os.Create(params.Output)
	if err != nil {
		return nil, fmt.Errorf("failed to create output file: %w", err)
	}
	defer newFile.Close()

	if err := sbom.WriteSBOM(newFile, sbomDoc); err != nil {
		return nil, fmt.Errorf("failed to write SBOM to file: %w", err)
	}

	summary := calculateSummary(responses, params.Verbose)

	return &summary, nil
}

// calculateSummary counts enriched/skipped/failed components
func calculateSummary(responses map[interface{}]clearlydef.DefinitionResponse, verbose bool) Summary {
	summary := Summary{}
	for _, resp := range responses {
		if resp.Licensed.Declared != "" {
			summary.Enriched++
		} else {
			summary.Skipped++
		}
	}
	if verbose {
		fmt.Printf("Enriched: %d, Skipped: %d, Failed: %d\n", summary.Enriched, summary.Skipped, summary.Failed)
		for _, err := range summary.Errors {
			fmt.Println("Error:", err)
		}
	}
	return summary
}
