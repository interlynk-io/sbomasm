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
	"crypto/sha256"
	"fmt"
	"os"
	"sort"
	"strconv"
	"time"

	"github.com/google/uuid"
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

// getTimestamp returns the timestamp to use for the SBOM.
// If SOURCE_DATE_EPOCH is set, it uses that value (Unix timestamp).
// Otherwise, returns the current time.
func getTimestamp() time.Time {
	if epochStr := os.Getenv("SOURCE_DATE_EPOCH"); epochStr != "" {
		if epoch, err := strconv.ParseInt(epochStr, 10, 64); err == nil {
			return time.Unix(epoch, 0).UTC()
		}
	}
	return time.Now().UTC()
}

// getDeterministicUUID generates a deterministic UUID v5 based on a hash of the component list.
// Used when SOURCE_DATE_EPOCH is set to produce reproducible SBOMs.
func getDeterministicUUID(components []Component) string {
	// Sort components by their unique identifier (PURL or name@version)
	sorted := make([]Component, len(components))
	copy(sorted, components)
	sort.Slice(sorted, func(i, j int) bool {
		keyI := componentKey(sorted[i])
		keyJ := componentKey(sorted[j])
		return keyI < keyJ
	})

	// Hash the sorted component list
	h := sha256.New()
	for _, c := range sorted {
		// Include fields that identify the component uniquely
		h.Write([]byte(c.Name))
		h.Write([]byte(c.Version))
		h.Write([]byte(c.PURL))
	}
	hash := h.Sum(nil)

	// Use first 16 bytes of hash to create a UUID
	var u uuid.UUID
	copy(u[:], hash[:16])

	// Set version (5) and variant bits for UUID v5 (name-based)
	u[6] = (u[6] & 0x0f) | 0x50 // Version 5
	u[8] = (u[8] & 0x3f) | 0x80 // Variant 10

	return u.String()
}

// getSerialNumber returns a serial number (UUID) for CycloneDX.
// If SOURCE_DATE_EPOCH is set, returns a deterministic UUID based on component hash.
// Otherwise, returns a random UUID.
func getSerialNumber(components []Component) string {
	if os.Getenv("SOURCE_DATE_EPOCH") != "" {
		return getDeterministicUUID(components)
	}
	return uuid.New().String()
}

// getDocumentNamespace returns a document namespace for SPDX.
// If SOURCE_DATE_EPOCH is set, returns a deterministic namespace based on component hash.
// Otherwise, returns a namespace with a random UUID.
func getDocumentNamespace(docName string, components []Component) string {
	var uid string
	if os.Getenv("SOURCE_DATE_EPOCH") != "" {
		uid = getDeterministicUUID(components)
	} else {
		uid = uuid.New().String()
	}
	return fmt.Sprintf("https://spdx.org/spdxdocs/%s-%s", docName, uid)
}
