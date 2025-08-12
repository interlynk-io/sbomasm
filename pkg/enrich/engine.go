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
	"github.com/interlynk-io/sbomasm/pkg/enrich/types"
	"github.com/interlynk-io/sbomasm/pkg/logger"
	sbomop "github.com/interlynk-io/sbomasm/pkg/sbom"
	"github.com/interlynk-io/sbomqs/pkg/sbom"
)

func Engine(ctx context.Context, args []string, params *types.EnrichParams) (*types.EnrichSummary, error) {
	// Initialize the enrich engine with the provided parameters

	log := logger.FromContext(ctx)
	log.Debugf("Starting Enrich Engine")
	sbomFile := args[0]

	// // get SBOM doc
	// sbomDoc, err := getSBOMDoc(ctx, sbomFile)
	// if err != nil {
	// 	return nil, err
	// }

	f, err := os.Open(sbomFile)
	if err != nil {
		return nil, fmt.Errorf("failed to open file %q: %w", sbomFile, err)
	}
	defer f.Close()

	sbomDoc, err := sbom.NewSBOMDocument(ctx, f, sbom.Signature{})
	if err != nil {
		log.Fatalf("failed to parse SBOM document: %w", err)
	}

	spec := sbomDoc.Spec().GetSpecType()

	// extract targets
	targets := extract.Extractor(sbomDoc, params.Fields, params.Force)

	coordinates := clearlydef.Mapper(ctx, spec, targets)
	log.Debugf("coordinates: %+v", coordinates)

	responses := clearlydef.Client(ctx, coordinates)

	sbomDoc = Enricher(sbomDoc, targets, responses, params.Force)

	newFile, err := os.Create(params.Output)
	if err != nil {
		return nil, fmt.Errorf("failed to create output file: %w", err)
	}
	defer newFile.Close()

	if err := sbomop.WriteSBOM(newFile, sbomDoc); err != nil {
		return nil, fmt.Errorf("failed to write SBOM to file: %w", err)
	}

	summary := calculateSummary(responses)

	return &summary, nil
}

func calculateSummary(responses map[sbom.GetComponent]clearlydef.DefinitionResponse) types.EnrichSummary {
	// Logic to count enriched/skipped/failed based on responses
	// Placeholder implementation
	enriched := 0
	skipped := 0
	failed := 0
	errors := []error{}

	for _, resp := range responses {
		if resp.Licensed.Declared != "" {
			enriched++
		} else {
			skipped++
		}
	}

	return types.EnrichSummary{Enriched: enriched, Skipped: skipped, Failed: failed, Errors: errors}
}

// func getSBOMDoc(ctx context.Context, sbomFile string) (sbom.SBOMDocument, error) {
// 	log := logger.FromContext(ctx)

// 	f, err := os.Open(sbomFile)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to open file %q: %w", sbomFile, err)
// 	}
// 	defer f.Close()

// 	spec, format, err := sbom.Detect(f)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to detect SBOM format: %w", err)
// 	}

// 	log.Debugf("Detected SBOM format: %s, spec: %s", format, spec)

// 	// rewind before parsing
// 	if _, err := f.Seek(0, io.SeekStart); err != nil {
// 		return nil, fmt.Errorf("failed to rewind file: %w", err)
// 	}

// 	// parse into SBOM object
// 	sbomDoc, err := sbom.ParseSBOM(f, spec, format)
// 	if err != nil {
// 		return nil, err
// 	}
// 	return sbomDoc, nil
// }
