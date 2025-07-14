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

	cydx "github.com/CycloneDX/cyclonedx-go"
	"github.com/interlynk-io/sbomasm/pkg/rm/types"
	"github.com/interlynk-io/sbomasm/pkg/sbom"
	"github.com/spdx/tools-golang/spdx/common"
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

	fmt.Println("Detected SBOM format:", format)
	fmt.Println("Detected SBOM spec:", spec)

	// rewind before parsing
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("failed to rewind file: %w", err)
	}

	// parse into SBOM object
	sbomDoc, err := sbom.ParseSBOM(f, spec, format)
	if err != nil {
		return err
	}

	// Cast the underlying raw doc to correct type for registration
	switch spec {
	case sbom.SBOMSpecCDX:
		RegisterHandlers(sbomDoc.Raw().(*cydx.BOM), nil)
	case sbom.SBOMSpecSPDX:
		RegisterHandlers(nil, sbomDoc.Raw().(common.AnyDocument))
	default:
		return fmt.Errorf("unsupported spec: %s", spec)
	}

	err = Remove(ctx, sbomDoc, params)
	if err != nil {
		return err
	}

	return fmt.Errorf("unsupported SBOM spec type: %s", spec)
}
