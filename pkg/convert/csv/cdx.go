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
	"strings"

	cydx "github.com/CycloneDX/cyclonedx-go"

	"github.com/interlynk-io/sbomasm/v2/pkg/logger"
	"github.com/interlynk-io/sbomasm/v2/pkg/sbom"
)

// writeCDX writes the given SBOM document to the provided CSV writer in a flattened format.
func writeCDX(ctx context.Context, doc sbom.SBOMDocument, w *csv.Writer) error {
	log := logger.FromContext(ctx)

	log.Debugf("writing CycloneDX SBOM document to csv format")

	bom, ok := doc.Document().(*cydx.BOM)
	if !ok {
		return fmt.Errorf("failed type coversion document to CycloneDX BOM")
	}

	log.Debugf("bom document is converted to CycloneDX BOM struct: %+v", bom)

	// write primary component first
	if bom.Metadata != nil && bom.Metadata.Component != nil {
		if err := w.Write(cdxComponentToRow(bom.Metadata.Component)); err != nil {
			return fmt.Errorf("writing metadata component row: %w", err)
		}
	}
	log.Debugf("primary component is written to csv output")

	// write all other components
	if bom.Components != nil {
		for i := range *bom.Components {
			if err := w.Write(cdxComponentToRow(&(*bom.Components)[i])); err != nil {
				return fmt.Errorf("writing component row: %w", err)
			}
		}
	}
	log.Debugf("%d other components are written to csv output", len(*bom.Components))

	return nil
}

/*
cdxComponentToRow converts a CycloneDX component to a CSV row representation.

The order of fields must match the header row defined in the CSV output.
The fields included are:

1. Name

2. Version

3. Type

4. Author

5. Supplier

6. Group

7. Scope

8. PackageURL

9. CPE

10. License Expressions (comma-separated if multiple)

11. License Names (comma-separated if multiple)

12. Copyright

13. Description

14. Hashes (MD5, SHA1, SHA256, SHA512)
*/
func cdxComponentToRow(c *cydx.Component) []string {
	return []string{
		c.Name,
		c.Version,
		string(c.Type),
		c.Author,
		cdxSupplierName(c.Supplier),
		c.Group,
		string(c.Scope),
		c.PackageURL,
		c.CPE,
		cdxLicenseExpressions(c.Licenses),
		cdxLicenseNames(c.Licenses),
		c.Copyright,
		c.Description,
		cdxHashValue(c.Hashes, cydx.HashAlgoMD5),
		cdxHashValue(c.Hashes, cydx.HashAlgoSHA1),
		cdxHashValue(c.Hashes, cydx.HashAlgoSHA256),
		cdxHashValue(c.Hashes, cydx.HashAlgoSHA512),
	}
}

// cdxSupplierName is a helper function to safely extract the supplier name from a CycloneDX component.
func cdxSupplierName(supplier *cydx.OrganizationalEntity) string {
	if supplier == nil {
		return ""
	}
	return supplier.Name
}

// cdxLicenseExpressions is a helper function to extract and
// concatenate license expressions from a CycloneDX component's licenses.
func cdxLicenseExpressions(licenses *cydx.Licenses) string {
	if licenses == nil {
		return ""
	}
	expressions := []string{}
	for _, l := range *licenses {
		if l.Expression != "" {
			expressions = append(expressions, l.Expression)
		}
	}
	return strings.Join(expressions, ", ")
}

// cdxLicenseNames is a helper function to extract and
// concatenate license names from a CycloneDX component's licenses.
func cdxLicenseNames(licenses *cydx.Licenses) string {
	if licenses == nil {
		return ""
	}
	names := []string{}
	for _, l := range *licenses {
		if l.License != nil && l.License.Name != "" {
			names = append(names, l.License.Name)
		} else if l.License != nil && l.License.ID != "" {
			names = append(names, l.License.ID)
		}
	}
	return strings.Join(names, ", ")
}

// cdxHashValue is a helper function to extract the value of a specific
// hash algorithm from a CycloneDX component's hashes.
func cdxHashValue(hashes *[]cydx.Hash, algo cydx.HashAlgorithm) string {
	if hashes == nil {
		return ""
	}
	for _, h := range *hashes {
		if h.Algorithm == algo {
			return h.Value
		}
	}
	return ""
}
