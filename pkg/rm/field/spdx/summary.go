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

package spdx

import (
	"fmt"
	"strings"

	"github.com/spdx/tools-golang/spdx"
)

func RenderSummaryAuthorFromMetadata(target []interface{}) {
	fmt.Println("📋 Summary of removed SPDX authors:")
	for _, entry := range target {
		if authorStr, ok := entry.(string); ok && strings.HasPrefix(authorStr, "Person:") {
			fmt.Printf("  - %s\n", authorStr)
		}
	}
}

func RenderSummaryLicenseFromMetadata(target []interface{}) {
	fmt.Println("📋 Summary of removed SPDX dataLicense:")
	for _, entry := range target {
		if lic, ok := entry.(string); ok {
			fmt.Printf("  - License: %s\n", lic)
		}
	}
}

func RenderSummaryLifecycleFromMetadata(target []interface{}) {
	fmt.Println("📋 Summary of removed SPDX lifecycle entries:")
	for _, entry := range target {
		if val, ok := entry.(string); ok {
			fmt.Printf("  - %s\n", val)
		}
	}
}

func RenderSummarySupplierFromMetadata(target []interface{}) {
	fmt.Println("📋 Summary of removed SPDX supplier entries:")
	for _, entry := range target {
		if creator, ok := entry.(spdx.Creator); ok {
			fmt.Printf("  - Supplier: %s (%s)\n", creator.Creator, creator.CreatorType)
		}
	}
}

func RenderSummaryToolFromMetadata(target []interface{}) {
	fmt.Println("📋 Summary of removed SPDX tool entries:")
	for _, entry := range target {
		if creator, ok := entry.(spdx.Creator); ok {
			fmt.Printf("  - Tool: %s (%s)\n", creator.Creator, creator.CreatorType)
		}
	}
}

func RenderSummaryTimestampFromMetadata(target []interface{}) {
	fmt.Println("📋 Summary of removed SPDX timestamp:")
	for _, entry := range target {
		if ts, ok := entry.(string); ok {
			fmt.Printf("  - Timestamp: %s\n", ts)
		}
	}
}

func RenderSummaryPurlFromComponent(entries []interface{}) {
	fmt.Println("Summary of components with purl:")
	for _, e := range entries {
		pkg, ok := e.(*spdx.Package)
		if !ok {
			continue
		}
		fmt.Printf("  - Name: %s, Version: %s\n", pkg.PackageName, pkg.PackageVersion)
	}
}

func RenderSummaryCopyrightFromComponent(entries []interface{}) []string {
	var summary []string
	for _, e := range entries {
		pkg, ok := e.(*spdx.Package)
		if !ok || pkg.PackageCopyrightText == "" {
			continue
		}
		summary = append(summary, fmt.Sprintf("Component: %s | Copyright: %s", pkg.PackageName, pkg.PackageCopyrightText))
	}
	return summary
}

func RenderSummaryCpeFromComponent(entries []interface{}) []string {
	var summary []string
	for _, e := range entries {
		pkg, ok := e.(*spdx.Package)
		if !ok {
			continue
		}
		for _, ref := range pkg.PackageExternalReferences {
			if strings.ToLower(ref.RefType) == "cpe" {
				summary = append(summary, fmt.Sprintf("Component: %s | CPE: %s", pkg.PackageName, ref.Locator))
			}
		}
	}
	return summary
}

func RenderSummaryDescriptionFromComponent(entries []interface{}) []string {
	var summary []string
	for _, e := range entries {
		pkg, ok := e.(*spdx.Package)
		if !ok || pkg.PackageDescription == "" {
			continue
		}
		summary = append(summary, fmt.Sprintf("Component: %s | Description: %s", pkg.PackageName, pkg.PackageDescription))
	}
	return summary
}

func RenderSummaryHashFromComponent(entries []interface{}) []string {
	var summary []string
	for _, e := range entries {
		pkg, ok := e.(*spdx.Package)
		if !ok || len(pkg.PackageChecksums) == 0 {
			continue
		}
		var checksums []string
		for _, checksum := range pkg.PackageChecksums {
			checksums = append(checksums, fmt.Sprintf("%s: %s", checksum.Algorithm, checksum.Value))
		}
		summary = append(summary, fmt.Sprintf("Component: %s | Hashes: %s", pkg.PackageName, strings.Join(checksums, "; ")))
	}
	return summary
}

func RenderSummaryLicenseFromComponent(entries []interface{}) []string {
	var summary []string
	for _, e := range entries {
		pkg, ok := e.(*spdx.Package)
		if !ok || len(pkg.PackageLicenseConcluded) == 0 {
			continue
		}
		summary = append(summary, fmt.Sprintf("Component: %s | License(s): %s", pkg.PackageName, pkg.PackageLicenseConcluded))
	}
	return summary
}

func RenderSummaryRepoFromComponent(entries []interface{}) []string {
	var summary []string
	for _, e := range entries {
		pkg, ok := e.(*spdx.Package)
		if !ok || pkg.PackageDownloadLocation == "" {
			continue
		}
		summary = append(summary, fmt.Sprintf("Component: %s | Repo: %s", pkg.PackageName, pkg.PackageDownloadLocation))
	}
	return summary
}

func RenderSummaryTypeFromComponent(entries []interface{}) []string {
	var summary []string
	for _, e := range entries {
		pkg, ok := e.(*spdx.Package)
		if !ok || pkg.PrimaryPackagePurpose == "" {
			continue
		}
		summary = append(summary, fmt.Sprintf("Component: %s | Type: %s", pkg.PackageName, pkg.PrimaryPackagePurpose))
	}
	return summary
}

func RenderSummarySupplierFromComponent(entries []interface{}) string {
	var b strings.Builder

	b.WriteString("Suppliers to be removed:\n")
	b.WriteString("-------------------------\n")

	for _, e := range entries {
		pkg, ok := e.(*spdx.Package)
		if !ok || pkg.PackageSupplier == nil {
			continue
		}

		fmt.Fprintf(&b, "Component: %s@%s\n", pkg.PackageName, pkg.PackageVersion)
		fmt.Fprintf(&b, "Supplier : %s\n", pkg.PackageSupplier.Supplier)
		b.WriteString("-------------------------\n")
	}

	return b.String()
}
