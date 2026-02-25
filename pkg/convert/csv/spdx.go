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

	"github.com/spdx/tools-golang/spdx/v2/common"
	spdx23 "github.com/spdx/tools-golang/spdx/v2/v2_3"

	"github.com/interlynk-io/sbomasm/v2/pkg/logger"
	"github.com/interlynk-io/sbomasm/v2/pkg/sbom"
)

// writeSPDX writes the given SBOM document to the
// provided CSV writer in a flattened format.
func writeSPDX(ctx context.Context, doc sbom.SBOMDocument, w *csv.Writer) error {
	log := logger.FromContext(ctx)

	spdxDoc, ok := doc.Document().(*spdx23.Document)
	if !ok {
		return fmt.Errorf("failed to cast document to SPDX document")
	}
	log.Debugf("writing SPDX SBOM document to csv format")

	// write all packages
	for _, p := range spdxDoc.Packages {
		if err := w.Write(spdxPackageToRow(p)); err != nil {
			return fmt.Errorf("writing package row: %w", err)
		}
	}
	log.Debugf("all %d components are written to csv output", len(spdxDoc.Packages))

	// write all files
	for _, f := range spdxDoc.Files {
		if err := w.Write(spdxFileToRow(f)); err != nil {
			return fmt.Errorf("writing file row: %w", err)
		}
	}
	log.Debugf("all %d files are written to csv output", len(spdxDoc.Files))

	return nil
}

/*
spdxPackageToRow converts an SPDX package to a CSV row representation.

The order of fields must match the header row defined in the CSV output.
The fields included are:

1. Name

2. Version

3. Type (emits PrimaryPackagePurpose verbatim, e.g. "APPLICATION", "LIBRARY"; blank if unset)

4. Author (extracted from PackageOriginator if it's a Person or Organization)

5. Supplier (extracted from PackageSupplier)

6. Group (no direct SPDX equivalent, left blank)

7. Scope (no direct SPDX equivalent, left blank)

8. PURL (extracted from external references of type "purl")

9. CPE (extracted from external references of type "cpe23Type" or "cpe22Type")

10. Declared License

11. License Comments

12. Copyright Text

13. Description

14. Checksums (MD5, SHA1, SHA256, SHA512)
*/
func spdxPackageToRow(p *spdx23.Package) []string {
	return []string{
		p.PackageName,
		p.PackageVersion,
		p.PrimaryPackagePurpose,
		spdxOriginatorName(p.PackageOriginator),
		spdxSupplierName(p.PackageSupplier),
		"", // Group   no SPDX equivalent
		"", // Scope   no SPDX equivalent
		spdxExtractPURL(p.PackageExternalReferences),
		spdxExtractCPE(p.PackageExternalReferences),
		p.PackageLicenseDeclared,
		p.PackageLicenseComments,
		p.PackageCopyrightText,
		p.PackageDescription,
		spdxChecksumValue(p.PackageChecksums, common.SHA1),
		spdxChecksumValue(p.PackageChecksums, common.MD5),
		spdxChecksumValue(p.PackageChecksums, common.SHA256),
		spdxChecksumValue(p.PackageChecksums, common.SHA512),
	}
}

/*
spdxFileToRow converts an SPDX file to a CSV row representation.

The order of fields must match the header row defined in the CSV output.
The fields included are:

1. Name (FileName in SPDX)

2. Version (files don't have versions in SPDX, left blank)

3. Type (set to "FILE" for SPDX files)

4. Author (no file-level author in SPDX, left blank)

5. Supplier (no file-level supplier in SPDX, left blank)

6. Group (no direct SPDX equivalent, left blank)

7. Scope (no direct SPDX equivalent, left blank)

8. PURL (files don't have PURLs in SPDX, left blank)

9. CPE (files don't have CPEs in SPDX, left blank)

10. Declared License (LicenseConcluded in SPDX)

11. License Comments

12. Copyright Text

13. Description (files don't have descriptions in SPDX, left blank)

14. Checksums (MD5, SHA1, SHA256, SHA512)
*/
func spdxFileToRow(f *spdx23.File) []string {
	return []string{
		f.FileName,
		"", // Version: files don't have versions in SPDX
		"FILE",
		"", // Author   no file-level author in SPDX
		"", // Supplier   no file-level supplier in SPDX
		"", // Group
		"", // Scope
		"", // Purl   files don't have PURLs in SPDX
		"", // Cpe   files don't have CPEs in SPDX
		f.LicenseConcluded,
		f.LicenseComments,
		f.FileCopyrightText,
		"", // Description   files don't have descriptions in SPDX
		spdxChecksumValue(f.Checksums, common.MD5),
		spdxChecksumValue(f.Checksums, common.SHA1),
		spdxChecksumValue(f.Checksums, common.SHA256),
		spdxChecksumValue(f.Checksums, common.SHA512),
	}
}

// spdxOriginatorName is a helper function to safely extract
// the originator name from an SPDX package originator.
func spdxOriginatorName(originator *common.Originator) string {
	if originator == nil {
		return ""
	}
	if originator.OriginatorType == "Person" {
		return originator.Originator
	}
	return ""
}

// spdxSupplierName is a helper function to safely extract
// the supplier name from an SPDX package supplier.
func spdxSupplierName(supplier *common.Supplier) string {
	if supplier == nil {
		return ""
	}
	return supplier.Supplier
}

// spdxExtractPURL is a helper function to extract the
// PURL from an SPDX package's external references.
func spdxExtractPURL(refs []*spdx23.PackageExternalReference) string {
	for _, r := range refs {
		if r.RefType == "purl" {
			return r.Locator
		}
	}
	return ""
}

// spdxExtractCPE is a helper function to extract the
// CPE from an SPDX package's external references.
func spdxExtractCPE(refs []*spdx23.PackageExternalReference) string {
	for _, r := range refs {
		if r.RefType == "cpe23Type" || r.RefType == "cpe22Type" {
			return r.Locator
		}
	}
	return ""
}

// spdxChecksumValue is a helper function to extract the
// value of a specific checksum algorithm
func spdxChecksumValue(checksums []common.Checksum, algo common.ChecksumAlgorithm) string {
	for _, c := range checksums {
		if c.Algorithm == algo {
			return c.Value
		}
	}
	return ""
}
