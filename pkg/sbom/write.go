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
	"fmt"
	"io"

	cydx "github.com/CycloneDX/cyclonedx-go"
	spdxjson "github.com/spdx/tools-golang/json"
	"github.com/spdx/tools-golang/spdx"
)

func WriteSBOM(w io.Writer, doc SBOMDocument) error {
	switch d := doc.Document().(type) {
	case *cydx.BOM:
		encoder := cydx.NewBOMEncoder(w, cydx.BOMFileFormatJSON)
		encoder.SetPretty(true)
		return encoder.Encode(d)

	case *spdx.Document:
		return spdxjson.Write(d, w)
	default:
		return fmt.Errorf("unsupported SBOM type for writing")
	}
}
