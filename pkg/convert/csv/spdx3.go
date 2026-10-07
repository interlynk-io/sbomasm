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

	"github.com/interlynk-io/sbomasm/v2/pkg/logger"
	"github.com/interlynk-io/sbomasm/v2/pkg/sbom"
	spdx "github.com/interlynk-io/spdx-zen/model/v3.0.1"
	"github.com/interlynk-io/spdx-zen/parse"
)

// writeSPDX3 writes the given SBOM document to the provided CSV writer
// in a flattened format. It handles SPDX 3.0 JSON-LD documents parsed
// by the spdx-zen library.
func writeSPDX3(ctx context.Context, doc sbom.SBOMDocument, w *csv.Writer) error {
	log := logger.FromContext(ctx)

	spdx3Doc, ok := doc.Document().(*parse.Document)
	if !ok {
		return fmt.Errorf("failed to cast document to SPDX 3.0 document")
	}

	log.Debugf("writing SPDX 3.0 SBOM to CSV output")

	// write all packages
	for _, p := range spdx3Doc.Packages {
		if err := w.Write(spdx3PackageToRow(spdx3Doc, p)); err != nil {
			return fmt.Errorf("writing package row: %w", err)
		}
	}

	log.Debugf("total %d components are written to CSV output", len(spdx3Doc.Packages))

	// write all files
	for _, f := range spdx3Doc.Files {
		if err := w.Write(spdx3FileToRow(spdx3Doc, f)); err != nil {
			return fmt.Errorf("writing file row: %w", err)
		}
	}

	log.Debugf("total %d files are written to CSV output", len(spdx3Doc.Files))

	log.Debugf("successfully completed writing SPDX 3.0 SBOM to CSV output")

	return nil
}

/*
spdx3PackageToRow converts an SPDX 3.0 package to a CSV row representation.

The order of fields must match the header row defined in the CSV output.
The fields included are:

1. Name

2. Version

3. Type (emits PrimaryPurpose verbatim, e.g. "application", "library"; blank if unset)

4. Author (resolved from originatedBy references to Person/Organization elements)

5. Supplier (resolved from suppliedBy reference to Organization/Person elements)

6. Group (no direct SPDX 3.0 equivalent, left blank)

7. Scope (no direct SPDX 3.0 equivalent, left blank)

8. PURL (extracted from externalIdentifier of type "packageUrl")

9. CPE (extracted from externalIdentifier of type "cpe23" or "cpe22")

10. Concluded/Declared License expressions

11. License names

12. Copyright Text

13. Description

14. Checksums (MD5, SHA1, SHA256, SHA512) from verifiedUsing
*/
func spdx3PackageToRow(doc *parse.Document, p *spdx.Package) []string {
	return []string{
		p.Name,
		p.PackageVersion,
		string(p.PrimaryPurpose),
		spdx3AuthorName(doc, p),
		spdx3SupplierName(doc, p),
		"", // Group: no SPDX 3.0 equivalent
		"", // Scope: no SPDX 3.0 equivalent
		spdx3ExtractPURL(p),
		spdx3ExtractCPE(p),
		spdx3LicenseExpressions(doc, p),
		spdx3LicenseNames(doc, p),
		p.CopyrightText,
		p.Description,
		spdx3HashValue(p.VerifiedUsing, spdx.HashAlgorithmMd5),
		spdx3HashValue(p.VerifiedUsing, spdx.HashAlgorithmSha1),
		spdx3HashValue(p.VerifiedUsing, spdx.HashAlgorithmSha256),
		spdx3HashValue(p.VerifiedUsing, spdx.HashAlgorithmSha512),
	}
}

/*
spdx3FileToRow converts an SPDX 3.0 file to a CSV row representation.

The order of fields must match the header row defined in the CSV output.
The fields included are:

1. Name (FileName in SPDX)

2. Version (files don't have versions in SPDX, left blank)

3. Type (set to "FILE" for SPDX files)

4. Author (no file-level author in SPDX, left blank)

5. Supplier (no file-level supplier in SPDX, left blank)

6. Group (no direct SPDX 3.0 equivalent, left blank)

7. Scope (no direct SPDX 3.0 equivalent, left blank)

8. PURL (files don't have PURLs in SPDX, left blank)

9. CPE (files don't have CPEs in SPDX, left blank)

10. Concluded License

11. License names

12. Copyright Text

13. Description (files don't have descriptions in SPDX, left blank)

14. Checksums (MD5, SHA1, SHA256, SHA512) from verifiedUsing
*/
func spdx3FileToRow(doc *parse.Document, f *spdx.File) []string {
	return []string{
		f.Name,
		"", // Version: files don't have versions
		"FILE",
		"", // Author: no file-level author
		"", // Supplier: no file-level supplier
		"", // Group
		"", // Scope
		"", // Purl: files don't have PURLs
		"", // Cpe: files don't have CPEs
		spdx3FileLicenseExpressions(doc, f),
		spdx3FileLicenseNames(doc, f),
		f.CopyrightText,
		"", // Description: files don't have descriptions
		spdx3HashValue(f.VerifiedUsing, spdx.HashAlgorithmMd5),
		spdx3HashValue(f.VerifiedUsing, spdx.HashAlgorithmSha1),
		spdx3HashValue(f.VerifiedUsing, spdx.HashAlgorithmSha256),
		spdx3HashValue(f.VerifiedUsing, spdx.HashAlgorithmSha512),
	}
}

// spdx3AuthorName resolves the originatedBy references on a package
// to Person names via the document indexes.
// In SPDX 3.0, author represents the individual(s) who created the
// component; only Person elements are considered.
func spdx3AuthorName(doc *parse.Document, p *spdx.Package) string {
	if len(p.OriginatedBy) == 0 {
		return ""
	}

	var names []string
	for _, agent := range p.OriginatedBy {
		spdxID := agent.GetSpdxID()
		if spdxID == "" {
			continue
		}
		if person := doc.GetPersonByID(spdxID); person != nil {
			names = append(names, person.Name)
		}
	}
	return strings.Join(names, ", ")
}

// spdx3SupplierName resolves the suppliedBy reference on a package
// to an Organization name via the document indexes.
// In SPDX 3.0, supplier represents the distributing entity; only
// Organization elements are considered.
func spdx3SupplierName(doc *parse.Document, p *spdx.Package) string {
	if p.SuppliedBy == nil {
		return ""
	}

	spdxID := p.SuppliedBy.GetSpdxID()
	if spdxID == "" {
		return ""
	}

	if org := doc.GetOrganizationByID(spdxID); org != nil {
		return org.Name
	}
	return ""
}

// spdx3ExtractPURL extracts the Package URL from a package's
// externalIdentifier list.
func spdx3ExtractPURL(p *spdx.Package) string {
	for _, ei := range p.ExternalIdentifier {
		if ei.ExternalIdentifierType == spdx.ExternalIdentifierTypePackageUrl {
			return ei.Identifier
		}
	}
	return ""
}

// spdx3ExtractCPE extracts the CPE identifier from a package's
// externalIdentifier list.
func spdx3ExtractCPE(p *spdx.Package) string {
	for _, ei := range p.ExternalIdentifier {
		if ei.ExternalIdentifierType == spdx.ExternalIdentifierTypeCpe23 ||
			ei.ExternalIdentifierType == spdx.ExternalIdentifierTypeCpe22 {
			return ei.Identifier
		}
	}
	return ""
}

// spdx3LicenseExpressions extracts concluded and declared license
// expressions for a package by following HAS_CONCLUDED_LICENSE and
// HAS_DECLARED_LICENSE relationships.
func spdx3LicenseExpressions(doc *parse.Document, p *spdx.Package) string {
	licInfo := doc.GetLicensesFor(p.SpdxID)
	if licInfo == nil {
		return ""
	}

	var expressions []string
	for _, lic := range licInfo.ConcludedLicenses {
		if name := spdx3LicenseDisplayName(lic); name != "" {
			expressions = append(expressions, name)
		}
	}
	for _, lic := range licInfo.DeclaredLicenses {
		if name := spdx3LicenseDisplayName(lic); name != "" {
			expressions = append(expressions, name)
		}
	}
	return strings.Join(expressions, ", ")
}

// spdx3LicenseNames extracts concluded and declared license names
// for a package. For named licenses, this returns the license name;
// for expressions, it returns the expression string.
func spdx3LicenseNames(doc *parse.Document, p *spdx.Package) string {
	licInfo := doc.GetLicensesFor(p.SpdxID)
	if licInfo == nil {
		return ""
	}

	var names []string
	for _, lic := range licInfo.ConcludedLicenses {
		if name := spdx3LicenseDisplayName(lic); name != "" {
			names = append(names, name)
		}
	}
	for _, lic := range licInfo.DeclaredLicenses {
		if name := spdx3LicenseDisplayName(lic); name != "" {
			names = append(names, name)
		}
	}
	return strings.Join(names, ", ")
}

// spdx3FileLicenseExpressions extracts concluded license expressions for a file.
func spdx3FileLicenseExpressions(doc *parse.Document, f *spdx.File) string {
	licInfo := doc.GetLicensesFor(f.SpdxID)
	if licInfo == nil {
		return ""
	}

	var expressions []string
	for _, lic := range licInfo.ConcludedLicenses {
		if name := spdx3LicenseDisplayName(lic); name != "" {
			expressions = append(expressions, name)
		}
	}
	for _, lic := range licInfo.DeclaredLicenses {
		if name := spdx3LicenseDisplayName(lic); name != "" {
			expressions = append(expressions, name)
		}
	}
	return strings.Join(expressions, ", ")
}

// spdx3FileLicenseNames extracts concluded license names for a file.
func spdx3FileLicenseNames(doc *parse.Document, f *spdx.File) string {
	licInfo := doc.GetLicensesFor(f.SpdxID)
	if licInfo == nil {
		return ""
	}

	var names []string
	for _, lic := range licInfo.ConcludedLicenses {
		if name := spdx3LicenseDisplayName(lic); name != "" {
			names = append(names, name)
		}
	}
	for _, lic := range licInfo.DeclaredLicenses {
		if name := spdx3LicenseDisplayName(lic); name != "" {
			names = append(names, name)
		}
	}
	return strings.Join(names, ", ")
}

// spdx3LicenseDisplayName returns a human-readable display name for
// an AnyLicenseInfo element.
func spdx3LicenseDisplayName(lic *spdx.AnyLicenseInfo) string {
	if lic == nil {
		return ""
	}
	// Prefer Name if available
	if lic.Name != "" {
		return lic.Name
	}
	// For LicenseExpression elements parsed as AnyLicenseInfo,
	// the Name may be empty and we need to look up the actual expression.
	// The GetLicensesFor method already populates Name for LicenseExpression.
	return lic.Name
}

// spdx3HashValue extracts the hash value of a specific algorithm
// from a slice of verifiedUsing entries.
func spdx3HashValue(verifiedUsing []interface{}, algo spdx.HashAlgorithm) string {
	for _, vu := range verifiedUsing {
		switch h := vu.(type) {
		case *spdx.Hash:
			if h.Algorithm == algo {
				return h.HashValue
			}
		case spdx.Hash:
			if h.Algorithm == algo {
				return h.HashValue
			}
		}
	}
	return ""
}
