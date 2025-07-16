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
