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

func Engine(ctx context.Context, params *Config) (*EnrichSummary, error) {
	// Initialize the enrich engine with the provided parameters

	log := logger.FromContext(ctx)
	log.Debugf("starting enrich engine")

	summary := NewEnrichSummary()

	// parse the SBOM document
	sbomDoc, err := sbom.Parser(ctx, params.SBOMFile)
	if err != nil {
		return nil, err
	}

	log.Debugf("parsed SBOM document successfully: %s", sbomDoc.SpecType())

	extractParams := &extract.Params{
		Fields: params.Fields,
		Force:  params.Force,
	}

	components, total, selected, err := extract.Components(ctx, sbomDoc, extractParams)
	if err != nil {
		return nil, err
	}

	// if no components were found, return early
	// if no components selected return early
	if total == 0 || selected == 0 {
		summary.TotalComponents = total
		summary.SelectedComponents = selected
		return summary, nil
	}

	summary.TotalComponents = total
	summary.SelectedComponents = selected

	// map the component to a clearlydefined coordinates
	componentsToCoordinateMappings := clearlydef.Mapper(ctx, components)

	// crawl the clearlydefined coordinates via client to get definitions
	responses, err := clearlydef.Client(ctx, componentsToCoordinateMappings, params.MaxRetries, params.MaxWait)
	if err != nil {
		return nil, err
	}

	// enrich the sbom
	sbomDoc, enriched, skipped, skippedReasons, err := Enricher(ctx, sbomDoc, components, responses, params.Force, params.LicenseExpressionJoinBy)
	if err != nil {
		return nil, err
	}

	// process the output
	if err := processOutput(ctx, sbomDoc, params); err != nil {
		return nil, err
	}

	summary.Enriched = enriched
	summary.Skipped = skipped
	summary.SkippedReasons = skippedReasons

	return summary, nil
}

func processOutput(ctx context.Context, sbomDoc sbom.SBOMDocument, params *Config) error {
	log := logger.FromContext(ctx)

	if params.Output != "" {
		newFile, err := os.Create(params.Output)
		if err != nil {
			return fmt.Errorf("failed to create output file: %w", err)
		}
		defer newFile.Close()

		if err := sbom.WriteSBOM(newFile, sbomDoc); err != nil {
			return fmt.Errorf("failed to write SBOM to file: %w", err)
		}
		log.Debugf("updated SBOM written to file: %s", params.Output)
	} else {
		if err := sbom.WriteSBOM(os.Stdout, sbomDoc); err != nil {
			return fmt.Errorf("failed to write SBOM to stdout: %w", err)
		}
		log.Debugf("no output file specified, writing to stdout")
	}

	return nil
}
