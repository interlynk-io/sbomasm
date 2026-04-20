// Copyright 2026 Interlynk.io
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package gsbom

import (
	"context"

	"github.com/interlynk-io/sbomasm/v2/pkg/logger"
	"github.com/interlynk-io/sbomasm/v2/pkg/sbom"
)

// Serialize calls the appropriate serialization function
// based on the specified format (CycloneDX or SPDX).
func Serialize(ctx context.Context, format string, bom *BOM, output string, specVersion string) error {
	log := logger.FromContext(ctx)
	log.Debugf("serializing BOM: format=%s, output=%s, specVersion=%s", format, output, specVersion)

	switch format {
	case string(sbom.SBOMSpecSPDX):
		return SerializeSPDX(ctx, bom, output, specVersion)

	case string(sbom.SBOMSpecCDX):
		return SerializeCycloneDX(ctx, bom, output, specVersion)

	default:
		log.Debugf("unknown format '%s', defaulting to CycloneDX", format)
		return SerializeCycloneDX(ctx, bom, output, specVersion)
	}
}
