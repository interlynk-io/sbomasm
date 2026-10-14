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
	"context"
	"fmt"

	"github.com/interlynk-io/sbomasm/v2/pkg/logger"
	"github.com/interlynk-io/sbomasm/v2/pkg/rm/types"
	"github.com/interlynk-io/spdx-zen/parse"
)

func SelectLifecycleFromMetadata(ctx context.Context, doc *parse.Document) ([]interface{}, error) {
	log := logger.FromContext(ctx)
	if doc == nil || len(doc.Sboms) == 0 {
		return nil, nil
	}

	var selected []interface{}
	for _, sbom := range doc.Sboms {
		if len(sbom.SbomType) > 0 {
			selected = append(selected, SbomEntry{Sbom: sbom, SbomType: sbom.SbomType})
		}
	}
	log.Debugf("Selected %d SPDX 3.0 lifecycle entries from Sbom elements", len(selected))
	return selected, nil
}

func FilterLifecycleFromMetadata(selected []interface{}, params *types.RmParams) ([]interface{}, error) {
	// No value-based filtering for lifecycle — remove all selected entries.
	return selected, nil
}

func RemoveLifecycleFromMetadata(ctx context.Context, doc *parse.Document, targets []interface{}) error {
	log := logger.FromContext(ctx)
	if doc == nil || len(doc.Sboms) == 0 {
		return nil
	}

	removedCount := 0
	for _, t := range targets {
		entry, ok := t.(SbomEntry)
		if !ok {
			continue
		}
		for _, sbom := range doc.Sboms {
			if sbom.SpdxID == entry.Sbom.SpdxID {
				removedCount += len(sbom.SbomType)
				sbom.SbomType = nil
				break
			}
		}
	}

	log.Debugf("Removed %d SPDX 3.0 lifecycle entries from Sbom elements", removedCount)
	return nil
}

func RenderSummaryLifecycleFromMetadata(selected []interface{}) {
	fmt.Printf("📋 Summary of removed lifecycle entries:\n")
	for _, item := range selected {
		entry, ok := item.(SbomEntry)
		if !ok {
			continue
		}
		for _, st := range entry.SbomType {
			fmt.Printf("  • Sbom %s: %s\n", entry.Sbom.SpdxID, st)
		}
	}
}
