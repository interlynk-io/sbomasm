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

func SelectRepositoryFromMetadata(ctx context.Context, doc *parse.Document) ([]interface{}, error) {
	log := logger.FromContext(ctx)
	if doc == nil || doc.SpdxDocument == nil || len(doc.SpdxDocument.ExternalRef) == 0 {
		return nil, nil
	}

	var selected []interface{}
	for i := range doc.SpdxDocument.ExternalRef {
		selected = append(selected, RepoEntry{Doc: doc.SpdxDocument, ExtRef: &doc.SpdxDocument.ExternalRef[i], ExtRefIdx: i})
	}
	log.Debugf("Selected %d SPDX 3.0 repository entries from SpdxDocument", len(selected))
	return selected, nil
}

func FilterRepositoryFromMetadata(selected []interface{}, params *types.RmParams) ([]interface{}, error) {
	// No value-based filtering for repository — remove all selected entries.
	return selected, nil
}

func RemoveRepositoryFromMetadata(ctx context.Context, doc *parse.Document, targets []interface{}) error {
	log := logger.FromContext(ctx)
	if doc == nil || doc.SpdxDocument == nil || len(doc.SpdxDocument.ExternalRef) == 0 {
		return nil
	}

	removedCount := len(doc.SpdxDocument.ExternalRef)
	doc.SpdxDocument.ExternalRef = nil
	log.Debugf("Removed %d SPDX 3.0 repository entries from SpdxDocument", removedCount)
	return nil
}

func RenderSummaryRepositoryFromMetadata(selected []interface{}) {
	fmt.Printf("📋 Summary of removed repository entries:\n")
	for _, item := range selected {
		entry, ok := item.(RepoEntry)
		if !ok {
			continue
		}
		for _, loc := range entry.ExtRef.Locator {
			fmt.Printf("  • %s (%s)\n", loc, entry.ExtRef.ExternalRefType)
		}
	}
}
