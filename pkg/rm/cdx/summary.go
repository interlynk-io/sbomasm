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

	cydx "github.com/CycloneDX/cyclonedx-go"
)

func RenderSummaryAuthor(selected []interface{}) {
	fmt.Println("📋 Summary of removed author entries:")
	for _, entry := range selected {
		if author, ok := entry.(cydx.OrganizationalContact); ok {
			fmt.Println("  - Author:")
			fmt.Printf("      ID:    %s\n", author.BOMRef)
			fmt.Printf("      Name:  %s\n", author.Name)
			fmt.Printf("      Email: %s\n", author.Email)
		}
	}
}

func RenderSummarySupplier(selected []interface{}) {
	fmt.Println("📋 Summary of removed supplier entries:")
	for _, entry := range selected {
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

func RenderSummaryTool(selected []interface{}) {
	fmt.Println("📋 Summary of removed tool entries:")
	for _, entry := range selected {
		if tool, ok := entry.(cydx.Tool); ok {
			fmt.Println("  - Tool:")
			fmt.Printf("      Name:    %s\n", tool.Name)
			fmt.Printf("      Version: %s\n", tool.Version)
			fmt.Printf("      Vendor:  %s\n", tool.Vendor)
		}
	}
}

func RenderSummaryLicense(selected []interface{}) {
	fmt.Println("📋 Summary of removed license entries:")
	for _, entry := range selected {
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
