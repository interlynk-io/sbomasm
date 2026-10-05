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

package spdx3

import (
	"fmt"
	"time"
)

func RenderSummaryAuthorFromMetadata(target []interface{}) {
	fmt.Println("📋 Summary of removed SPDX 3.0 authors:")
	if len(target) == 0 {
		fmt.Println("  - No authors selected for removal")
		return
	}
	for _, entry := range target {
		if e, ok := entry.(PersonEntry); ok && e.Person != nil {
			fmt.Printf("  - %s (%s)\n", e.Person.Name, e.SpdxID)
		}
	}
}

func RenderSummarySupplierFromMetadata(target []interface{}) {
	fmt.Println("📋 Summary of removed SPDX 3.0 suppliers:")
	if len(target) == 0 {
		fmt.Println("  - No suppliers selected for removal")
		return
	}
	for _, entry := range target {
		if e, ok := entry.(OrgEntry); ok && e.Organization != nil {
			fmt.Printf("  - %s (%s)\n", e.Organization.Name, e.SpdxID)
		}
	}
}

func RenderSummaryToolFromMetadata(target []interface{}) {
	fmt.Println("📋 Summary of removed SPDX 3.0 tools:")
	if len(target) == 0 {
		fmt.Println("  - No tools selected for removal")
		return
	}
	for _, entry := range target {
		if e, ok := entry.(ToolEntry); ok && e.Tool != nil {
			fmt.Printf("  - %s (%s)\n", e.Tool.Name, e.SpdxID)
		}
	}
}

func RenderSummaryTimestampFromMetadata(target []interface{}) {
	fmt.Println("📋 Summary of removed SPDX 3.0 timestamp:")
	for _, entry := range target {
		if ts, ok := entry.(time.Time); ok {
			fmt.Printf("  - %s\n", ts.Format(time.RFC3339))
		}
	}
}

func RenderSummaryLicenseFromMetadata(target []interface{}) {
	fmt.Println("📋 Summary of removed SPDX 3.0 dataLicense:")
	for _, entry := range target {
		if e, ok := entry.(LicenseEntry); ok && e.License != nil {
			fmt.Printf("  - %s\n", e.License.SpdxID)
		}
	}
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen]
}
