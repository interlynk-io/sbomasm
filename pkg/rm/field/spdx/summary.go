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
	"regexp"
	"strings"

	"github.com/spdx/tools-golang/spdx"
)

func RenderSummaryAuthorFromMetadata(target []interface{}) {
	fmt.Println("📋 Summary of removed SPDX authors:")

	if len(target) == 0 {
		fmt.Println("  - No authors selected for removal")
		return
	}

	for _, entry := range target {
		author, ok := entry.(spdx.Creator)
		if ok {
			fmt.Printf("  - %s\n", author.Creator)
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

func RenderSummaryAuthorFromComponent(entries []interface{}) {
	fmt.Println("Summary of author entries to be removed:")
	if len(entries) == 0 {
		fmt.Println("No author entries selected for removal")
		return
	}

	for _, e := range entries {
		entry, ok := e.(AuthorEntry)
		if !ok || entry.Originator == nil {
			fmt.Println("Skipping invalid author entry:", e)
			continue
		}

		// Extract email for display
		email := "<no email>"
		re := regexp.MustCompile(`\(([^)]+)\)`)
		if matches := re.FindStringSubmatch(entry.Originator.Originator); len(matches) > 1 {
			email = matches[1]
		}
		fmt.Printf("  - Component: %s@%s, Author: %s (%s)\n",
			entry.Package.PackageName,
			entry.Package.PackageVersion,
			entry.Originator.Originator,
			email)
	}
}

func RenderSummarySupplierFromComponent(entries []interface{}) {
	fmt.Println("Summary of supplier entries to be removed:")
	if len(entries) == 0 {
		fmt.Println("No supplier entries selected for removal")
		return
	}

	for _, e := range entries {
		entry, ok := e.(SupplierEntry)
		if !ok || entry.Supplier == nil {
			fmt.Println("Skipping invalid supplier entry:", e)
			continue
		}
		fmt.Printf("  - Component: %s@%s, Supplier: %s\n",
			entry.Package.PackageName,
			entry.Package.PackageVersion,
			entry.Supplier.Supplier)
		if strings.EqualFold(entry.Supplier.Supplier, "NOASSERTION") {
			fmt.Println("    Note: NOASSERTION matched for supplier")
		}
	}
}

func RenderSummaryCopyrightFromComponent(entries []interface{}) {
	fmt.Println("Summary of copyright entries to be removed:")
	if len(entries) == 0 {
		fmt.Println("No copyright entries selected for removal")
		return
	}

	for _, e := range entries {
		entry, ok := e.(CopyrightEntry)
		if !ok || entry.Value == "" {
			fmt.Println("Skipping invalid copyright entry:", e)
			continue
		}
		fmt.Printf("  - Component: %s@%s, Copyright: %s\n",
			entry.Package.PackageName,
			entry.Package.PackageVersion,
			entry.Value)
		if strings.EqualFold(entry.Value, "NOASSERTION") {
			fmt.Println("    Note: NOASSERTION matched for copyright")
		}
	}
}

func RenderSummaryCpeFromComponent(entries []interface{}) {
	fmt.Println("Summary of CPE entries to be removed:")
	if len(entries) == 0 {
		fmt.Println("No CPE entries selected for removal")
		return
	}

	for _, e := range entries {
		entry, ok := e.(CpeEntry)
		if !ok || entry.Ref == nil || (entry.Ref.RefType != "cpe22Type" && entry.Ref.RefType != "cpe23Type") {
			fmt.Println("Skipping invalid CPE entry:", e)
			continue
		}
		fmt.Printf("  - Component: %s@%s, CPE: %s (%s)\n",
			entry.Package.PackageName,
			entry.Package.PackageVersion,
			entry.Ref.Locator,
			entry.Ref.RefType)
	}
}

func RenderSummaryDescriptionFromComponent(entries []interface{}) {
	fmt.Println("Summary of description entries to be removed:")
	if len(entries) == 0 {
		fmt.Println("No description entries selected for removal")
		return
	}

	for _, e := range entries {
		entry, ok := e.(DescriptionEntry)
		if !ok || entry.Value == "" {
			fmt.Println("Skipping invalid description entry:", e)
			continue
		}
		fmt.Printf("  - Component: %s@%s, Description: %s\n",
			entry.Package.PackageName,
			entry.Package.PackageVersion,
			entry.Value)
	}
}

func RenderSummaryHashFromComponent(entries []interface{}) {
	fmt.Println("Summary of hash entries to be removed:")
	if len(entries) == 0 {
		fmt.Println("No hash entries selected for removal")
		return
	}

	for _, e := range entries {
		entry, ok := e.(HashEntry)
		if !ok || entry.Checksum == nil {
			fmt.Println("Skipping invalid hash entry:", e)
			continue
		}
		fmt.Printf("  - Component: %s@%s, Hash: %s (%s)\n",
			entry.Package.PackageName,
			entry.Package.PackageVersion,
			entry.Checksum.Value,
			entry.Checksum.Algorithm)
	}
}

func RenderSummaryLicenseFromComponent(entries []interface{}) {
	fmt.Println("Summary of license entries to be removed:")
	if len(entries) == 0 {
		fmt.Println("No license entries selected for removal")
		return
	}

	for _, e := range entries {
		entry, ok := e.(LicenseEntry)
		if !ok || entry.Value == "" {
			fmt.Println("Skipping invalid license entry:", e)
			continue
		}
		fmt.Printf("  - Component: %s@%s, License: %s\n",
			entry.Package.PackageName,
			entry.Package.PackageVersion,
			entry.Value)
		if strings.EqualFold(entry.Value, "NOASSERTION") {
			fmt.Println("    Note: NOASSERTION matched for license")
		}
	}
}

func RenderSummaryRepoFromComponent(entries []interface{}) {
	fmt.Println("Summary of repository entries to be removed:")
	if len(entries) == 0 {
		fmt.Println("No repository entries selected for removal")
		return
	}

	for _, e := range entries {
		entry, ok := e.(RepositoryEntry)
		if !ok || entry.Value == "" {
			fmt.Println("Skipping invalid repository entry:", e)
			continue
		}
		fmt.Printf("  - Component: %s@%s, Repository: %s\n",
			entry.Package.PackageName,
			entry.Package.PackageVersion,
			entry.Value)
	}
}

func RenderSummaryTypeFromComponent(entries []interface{}) {
	fmt.Println("Summary of type entries to be removed:")
	if len(entries) == 0 {
		fmt.Println("No type entries selected for removal")
		return
	}

	for _, e := range entries {
		entry, ok := e.(TypeEntry)
		if !ok || entry.Value == "" {
			fmt.Println("Skipping invalid type entry:", e)
			continue
		}
		fmt.Printf("  - Component: %s@%s, Type: %s\n",
			entry.Package.PackageName,
			entry.Package.PackageVersion,
			entry.Value)
	}
}

func RenderSummaryPurlFromComponent(entries []interface{}) {
	fmt.Println("Summary of purl entries to be removed:")
	if len(entries) == 0 {
		fmt.Println("No purl entries selected for removal")
		return
	}

	for _, e := range entries {
		entry, ok := e.(PurlEntry)
		if !ok || entry.Ref == nil || entry.Ref.RefType != "purl" {
			fmt.Println("Skipping invalid purl entry:", e)
			continue
		}
		fmt.Printf("  - Component: %s@%s, PURL: %s\n",
			entry.Package.PackageName,
			entry.Package.PackageVersion,
			entry.Ref.Locator)
	}
}
