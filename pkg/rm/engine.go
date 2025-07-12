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

package rm

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/interlynk-io/sbomasm/pkg/rm/types"
	"github.com/interlynk-io/sbomasm/pkg/sbom"
)

func Engine(ctx context.Context, args []string, params *types.RmParams) error {
	inputFile := args[0]
	if inputFile == "" {
		return errors.New("input file path not provided")
	}

	// open sbom file
	f, err := os.Open(inputFile)
	if err != nil {
		return fmt.Errorf("failed to open file %q: %w", inputFile, err)
	}
	defer f.Close()

	// detect sbom format
	spec, format, err := sbom.Detect(f)
	if err != nil {
		return fmt.Errorf("failed to detect SBOM format: %w", err)
	}

	fmt.Println("Detected SBOM format:", spec)

	// rewind before parsing
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("failed to rewind file: %w", err)
	}

	// parse into SBOM object
	sbomDoc, err := sbom.ParseSBOM(f, spec, format)
	if err != nil {
		return err
	}

	err = Remove(ctx, sbomDoc, params)
	if err != nil {
		return err
	}
	// switch spec {
	// case sbom.SBOMSpecCDX:
	// 	cdxDoc, ok := sbomDoc.(*sbom.CycloneDXDocument)
	// 	if !ok {
	// 		return fmt.Errorf("expected CycloneDX document, got %T", sbomDoc)
	// 	}
	// 	bom := cdxDoc.BOM

	// 	return rmCycloneDX(ctx, bom, params)

	// case sbom.SBOMSpecSPDX:
	// 	_, ok := sbomDoc.(*sbom.SPDXDocument)
	// 	if !ok {
	// 		return fmt.Errorf("expected SPDX document, got %T", sbomDoc)
	// 	}
	// 	// return rmSPDX(ctx, spdxDoc.Doc, params)

	// case sbom.SBOMSpecUnknown:
	// 	return fmt.Errorf("unknown SBOM spec type detected")

	// default:
	// 	return fmt.Errorf("unsupported SBOM spec type: %s", spec)
	// }
	return fmt.Errorf("unsupported SBOM spec type: %s", spec)
}
