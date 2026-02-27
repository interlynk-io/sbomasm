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

package csv

import (
	"context"
	"encoding/csv"
	"fmt"
	"io"

	"github.com/interlynk-io/sbomasm/v2/pkg/logger"
	"github.com/interlynk-io/sbomasm/v2/pkg/sbom"
)

/*
var headers defines the CSV header row for the flattened SBOM output. The fields included are:

1. Name: The name of the component or file.

2. Version: The version of the component, if applicable.

3. Type: The type of the entry (e.g., "PACKAGE" for SPDX packages, "FILE" for SPDX files, or the component type for CycloneDX).

4. Author: The author of the component, if available (extracted from SPDX PackageOriginator or CycloneDX Component's author field).

5. Supplier: The supplier of the component, if available (extracted from SPDX PackageSupplier or CycloneDX Component's supplier field).

6. Group: The group or namespace of the component, if available (extracted from CycloneDX Component's group field).

7. Scope: The scope of the component, if available (extracted from CycloneDX Component's scope field).

8. Purl: The Package URL (PURL) of the component, if available (extracted from CycloneDX Component's purl field).

9. Cpe: The Common Platform Enumeration (CPE) identifier of the component, if available (extracted from CycloneDX Component's cpe field).

10. LicenseExpressions: A comma-separated list of license expressions associated with the component.

11. LicenseNames: A comma-separated list of license names associated with the component.

12. Copyright: The copyright information for the component, if available (extracted from SPDX PackageCopyrightText or CycloneDX Component's copyright field).

13. Description: A description of the component, if available (extracted from SPDX PackageDescription or CycloneDX Component's description field).

14. MD5: The MD5 hash of the file, if applicable (extracted from CycloneDX Component's hashes).

15. SHA-1: The SHA-1 hash of the file, if applicable (extracted from CycloneDX Component's hashes).

16. SHA-256: The SHA-256 hash of the file, if applicable (extracted from CycloneDX Component's hashes).

17. SHA-512: The SHA-512 hash of the file, if applicable (extracted from CycloneDX Component's hashes).
*/
var headers = []string{
	"Name",
	"Version",
	"Type",
	"Author",
	"Supplier",
	"Group",
	"Scope",
	"Purl",
	"Cpe",
	"LicenseExpressions",
	"LicenseNames",
	"Copyright",
	"Description",
	"MD5",
	"SHA-1",
	"SHA-256",
	"SHA-512",
}

// Serialize writes the SBOM document as CSV to the given writer
func Serialize(ctx context.Context, doc sbom.SBOMDocument, out io.Writer) error {
	log := logger.FromContext(ctx)

	log.Debugf("intializing serialization process of SBOM document to CSV format")

	w := csv.NewWriter(out)
	defer w.Flush()

	// first write header row
	if err := w.Write(headers); err != nil {
		return fmt.Errorf("writing csv headers: %w", err)
	}

	log.Debugf("writing headers to CSV document: %v", headers)

	// dispatch based on spec type
	switch doc.SpecType() {
	case string(sbom.SBOMSpecCDX):
		return writeCDX(ctx, doc, w)

	case string(sbom.SBOMSpecSPDX):
		return writeSPDX(ctx, doc, w)

	default:
		return fmt.Errorf("unsupported spec type: %s", doc.SpecType())
	}
}
