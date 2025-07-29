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

package cdx

import (
	"fmt"
	"strings"

	cydx "github.com/CycloneDX/cyclonedx-go"
)

func RenderSummaryAuthorFromMetadata(target []interface{}) {
	fmt.Println("📋 Summary of removed author entries:")
	for _, entry := range target {
		if author, ok := entry.(cydx.OrganizationalContact); ok {
			fmt.Println("  - Author:")
			fmt.Printf("      ID:    %s\n", author.BOMRef)
			fmt.Printf("      Name:  %s\n", author.Name)
			fmt.Printf("      Email: %s\n", author.Email)
		}
	}
}

func RenderSummarySupplierFromMetadata(target []interface{}) {
	fmt.Println("📋 Summary of removed supplier entries:")
	for _, entry := range target {
		if supplier, ok := entry.(cydx.OrganizationalEntity); ok {
			fmt.Println("  - Supplier:")
			fmt.Printf("      Name: %s\n", supplier.Name)
			fmt.Printf("      URL: %s\n", *supplier.URL)

			if supplier.Contact != nil {
				for _, contact := range *supplier.Contact {
					fmt.Printf("      Contact: %s <%s>\n", contact.Name, contact.Email)
				}
			}
		}
	}
}

func RenderSummaryToolFromMetadata(target []interface{}) {
	fmt.Println("📋 Summary of removed tool entries:")
	for _, entry := range target {
		switch tools := entry.(type) {
		case []cydx.Tool:
			for _, tool := range tools {
				fmt.Println("  - Tool:")
				fmt.Printf("      Name:    %s\n", tool.Name)
				fmt.Printf("      Version: %s\n", tool.Version)
				fmt.Printf("      Vendor:  %s\n", tool.Vendor)
				fmt.Println()
			}
		case []cydx.Component:
			for _, tool := range tools {
				fmt.Println("  - Tool (as Component):")
				fmt.Printf("      Name:    %s\n", tool.Name)
				fmt.Printf("      Version: %s\n", tool.Version)
				fmt.Printf("      Type:    %s\n", tool.Type)
				fmt.Println()
			}
		default:
			fmt.Printf("  - Unknown tool entry: %v\n", entry)
		}
	}
}

func RenderSummaryLicenseFromMetadata(target []interface{}) {
	fmt.Println("📋 Summary of removed license entries:")
	for _, entry := range target {
		if lic, ok := entry.(cydx.LicenseChoice); ok {
			fmt.Println("  - License:")
			if lic.Expression != "" {
				fmt.Printf("      Expression: %s\n", lic.Expression)
			} else if lic.License != nil {
				fmt.Printf("      ID:   %s\n", lic.License.ID)
				fmt.Printf("      Name: %s\n", lic.License.Name)
			}
		}
	}
}

func RenderSummaryLifecycleFromMetadata(selected []interface{}) {
	fmt.Println("📋 Summary of removed lifecycle entries:")
	for _, entry := range selected {
		if lc, ok := entry.(cydx.Lifecycle); ok {
			fmt.Println("  - Lifecycle:")
			fmt.Printf("      Phase: %s\n", lc.Phase)
			if lc.Description != "" {
				fmt.Printf("      Description: %s\n", lc.Description)
			}
		}
	}
}

func RenderSummaryRepositoryFromMetadata(selected []interface{}) {
	fmt.Println("📋 Summary of removed repository (VCS) entries:")
	for _, entry := range selected {
		if extRefs, ok := entry.([]cydx.ExternalReference); ok {
			for _, ref := range extRefs {
				fmt.Println("  - Repository:")
				fmt.Printf("      Type:    %s\n", ref.Type)
				fmt.Printf("      URL:     %s\n", ref.URL)
				if ref.Comment != "" {
					fmt.Printf("      Comment: %s\n", ref.Comment)
				}
			}
		}
	}
}

func RenderSummaryTimestampFromMetadata(selected []interface{}) {
	fmt.Println("📋 Summary of removed timestamp:")
	if timestamp, ok := selected[0].(string); ok {
		fmt.Printf("  - Timestamp: %s\n", timestamp)
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
		if !ok || entry.Author == nil {
			fmt.Println("Skipping invalid author entry:", e)
			continue
		}
		email := entry.Author.Email
		if email == "" {
			email = "<no email>"
		}
		fmt.Printf("  - Component: %s@%s, Author: %s (%s)\n",
			entry.Component.Name,
			entry.Component.Version,
			entry.Author.Name,
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
		if !ok || entry.Value == nil {
			fmt.Println("Skipping invalid supplier entry:", e)
			continue
		}
		fmt.Printf("  - Component: %s@%s, Supplier: %s\n",
			entry.Component.Name,
			entry.Component.Version,
			entry.Value)

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
			entry.Component.Name,
			entry.Component.Version,
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
		if !ok || entry.Ref == "" {
			fmt.Println("Skipping invalid CPE entry:", e)
			continue
		}
		fmt.Printf("  - Component: %s@%s, CPE: %s\n",
			entry.Component.Name,
			entry.Component.Version,
			entry.Ref)
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
			entry.Component.Name,
			entry.Component.Version,
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
		if !ok || entry.Hash == nil {
			fmt.Println("Skipping invalid hash entry:", e)
			continue
		}
		fmt.Printf("  - Component: %s@%s, Hash: %s (%s)\n",
			entry.Component.Name,
			entry.Component.Version,
			entry.Hash.Value,
			entry.Hash.Algorithm)
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
			entry.Component.Name,
			entry.Component.Version,
			entry.Value)
		if strings.EqualFold(entry.Value, "NOASSERTION") {
			fmt.Println("    Note: NOASSERTION matched for license")
		}
	}
}

func RenderSummaryPurlFromComponent(entries []interface{}) {
	fmt.Println("Summary of PURL entries to be removed:")
	if len(entries) == 0 {
		fmt.Println("No PURL entries selected for removal")
		return
	}

	for _, e := range entries {
		entry, ok := e.(PurlEntry)
		if !ok || entry.Value == "" {
			fmt.Println("Skipping invalid PURL entry:", e)
			continue
		}
		fmt.Printf("  - Component: %s@%s, PURL: %s\n",
			entry.Component.Name,
			entry.Component.Version,
			entry.Value)
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
		if !ok || entry.Ref == nil || (entry.Ref.Type != cydx.ERTypeVCS && entry.Ref.Type != cydx.ERTypeDistribution) {
			fmt.Println("Skipping invalid repository entry:", e)
			continue
		}
		fmt.Printf("  - Component: %s@%s, Repository: %s (%s)\n",
			entry.Component.Name,
			entry.Component.Version,
			entry.Ref.URL,
			entry.Ref.Type)
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
			entry.Component.Name,
			entry.Component.Version,
			entry.Value)
	}
}
