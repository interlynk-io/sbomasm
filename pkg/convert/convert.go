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

package convert

import (
	"context"
	"fmt"
	"os"

	"github.com/interlynk-io/sbomasm/v2/pkg/convert/csv"
	"github.com/interlynk-io/sbomasm/v2/pkg/logger"
	"github.com/interlynk-io/sbomasm/v2/pkg/sbom"
)

// ConvertParams holds all parameters for the convert command
type ConvertParams struct {
	Ctx    *context.Context
	Input  string
	Output string
	Format string
}

// NewConvertParams returns a ConvertParams with sensible defaults
func NewConvertParams() *ConvertParams {
	return &ConvertParams{
		Format: "csv",
	}
}

// Convert parses the input SBOM and serializes it to the requested format
func Convert(p *ConvertParams) error {
	log := logger.FromContext(*p.Ctx)

	// parse input sbom into SBOMDocument
	doc, err := sbom.Parser(*p.Ctx, p.Input)
	if err != nil {
		return fmt.Errorf("parsing sbom file: %w", err)
	}

	log.Debugf("sbom file is parsed to sbom document: %+v", doc)

	// resolve output writer
	out := os.Stdout
	if p.Output != "" {
		f, err := os.Create(p.Output)
		if err != nil {
			return fmt.Errorf("creating output file: %w", err)
		}
		defer f.Close()
		out = f
	}

	log.Debugf("output will be written to %s", p.Output)

	// dispatch to format serializer
	switch p.Format {
	case "csv":
		log.Debugf("serializing sbom document to format %s", p.Format)
		return csv.Serialize(*p.Ctx, doc, out)

	default:
		return fmt.Errorf("unsupported output format: %s", p.Format)
	}
}
