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
	"strings"
)

func RenderSummaryHashFromComponent(target []interface{}) {
	fmt.Println("📋 Summary of removed component hashes:")
	if len(target) == 0 {
		fmt.Println("  - No hashes selected for removal")
		return
	}
	for _, entry := range target {
		if e, ok := entry.(ComponentHashEntry); ok {
			fmt.Printf("  - %s: %s = %s\n", e.Component.Name, e.Hash.Algorithm, truncate(e.Hash.HashValue, 16))
		}
	}
}

func RenderSummaryPurlFromComponent(target []interface{}) {
	fmt.Println("📋 Summary of removed component PURLs:")
	if len(target) == 0 {
		fmt.Println("  - No PURLs selected for removal")
		return
	}
	for _, entry := range target {
		if e, ok := entry.(ComponentExternalIdentifierEntry); ok {
			fmt.Printf("  - %s: %s\n", e.Component.Name, e.ExtId.Identifier)
		}
	}
}

func RenderSummaryCpeFromComponent(target []interface{}) {
	fmt.Println("📋 Summary of removed component CPEs:")
	if len(target) == 0 {
		fmt.Println("  - No CPEs selected for removal")
		return
	}
	for _, entry := range target {
		if e, ok := entry.(ComponentExternalIdentifierEntry); ok {
			fmt.Printf("  - %s: %s\n", e.Component.Name, e.ExtId.Identifier)
		}
	}
}

func RenderSummaryRepoFromComponent(target []interface{}) {
	fmt.Println("📋 Summary of removed component repositories:")
	if len(target) == 0 {
		fmt.Println("  - No repositories selected for removal")
		return
	}
	for _, entry := range target {
		if e, ok := entry.(ComponentExternalRefEntry); ok {
			locatorStr := strings.Join(e.ExtRef.Locator, ", ")
			fmt.Printf("  - %s: %s\n", e.Component.Name, locatorStr)
		}
	}
}

func RenderSummaryLicenseFromComponent(target []interface{}) {
	fmt.Println("📋 Summary of removed component licenses:")
	if len(target) == 0 {
		fmt.Println("  - No licenses selected for removal")
		return
	}
	for _, entry := range target {
		if e, ok := entry.(ComponentLicenseEntry); ok {
			fmt.Printf("  - %s: %s\n", e.Component.Name, e.LicenseExpr)
		}
	}
}

func RenderSummaryTypeFromComponent(target []interface{}) {
	fmt.Println("📋 Summary of removed component types:")
	if len(target) == 0 {
		fmt.Println("  - No types selected for removal")
		return
	}
	for _, entry := range target {
		if e, ok := entry.(ComponentTypeEntry); ok {
			fmt.Printf("  - %s: %s\n", e.Component.Name, e.Value)
		}
	}
}

func RenderSummaryDescriptionFromComponent(target []interface{}) {
	fmt.Println("📋 Summary of removed component descriptions:")
	if len(target) == 0 {
		fmt.Println("  - No descriptions selected for removal")
		return
	}
	for _, entry := range target {
		if e, ok := entry.(ComponentDescriptionEntry); ok {
			fmt.Printf("  - %s: %s...\n", e.Component.Name, truncate(e.Value, 30))
		}
	}
}

func RenderSummaryCopyrightFromComponent(target []interface{}) {
	fmt.Println("📋 Summary of removed component copyrights:")
	if len(target) == 0 {
		fmt.Println("  - No copyrights selected for removal")
		return
	}
	for _, entry := range target {
		if e, ok := entry.(ComponentCopyrightEntry); ok {
			fmt.Printf("  - %s: %s...\n", e.Component.Name, truncate(e.Value, 30))
		}
	}
}

func RenderSummaryAuthorFromComponent(target []interface{}) {
	fmt.Println("📋 Summary of removed component authors:")
	if len(target) == 0 {
		fmt.Println("  - No authors selected for removal")
		return
	}
	for _, entry := range target {
		if e, ok := entry.(ComponentAuthorEntry); ok {
			fmt.Printf("  - %s: %s\n", e.Component.Name, e.Person.Name)
		}
	}
}

func RenderSummarySupplierFromComponent(target []interface{}) {
	fmt.Println("📋 Summary of removed component suppliers:")
	if len(target) == 0 {
		fmt.Println("  - No suppliers selected for removal")
		return
	}
	for _, entry := range target {
		if e, ok := entry.(ComponentSupplierEntry); ok {
			fmt.Printf("  - %s: %s\n", e.Component.Name, e.Org.Name)
		}
	}
}
