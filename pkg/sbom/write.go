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

package sbom

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/interlynk-io/spdx-zen/parse"
	"github.com/interlynk-io/spdx-zen/serialize"
	"github.com/spdx/tools-golang/spdx"
)

// WriteSBOM serializes the given SBOMDocument to w in its native format.
// It supports CycloneDX (JSON), SPDX 2.x (JSON), and SPDX 3.0 (JSON-LD).
func WriteSBOM(w io.Writer, doc SBOMDocument) error {
	switch d := doc.Document().(type) {
	case *cyclonedx.BOM:
		encoder := cyclonedx.NewBOMEncoder(w, cyclonedx.BOMFileFormatJSON)
		encoder.SetPretty(true)
		return encoder.Encode(d)

	case *spdx.Document:
		output, err := json.MarshalIndent(d, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal SPDX document: %w", err)
		}
		_, err = w.Write(output)
		if err != nil {
			return fmt.Errorf("failed to write SPDX document: %w", err)
		}
		return nil

	case *parse.Document:
		writer := serialize.NewWriter(serialize.WithIndent("  "))
		return writer.Write(d, w)

	default:
		return fmt.Errorf("unsupported SBOM type for writing: %T", d)
	}
}
