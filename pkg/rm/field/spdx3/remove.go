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

	"time"

	"github.com/interlynk-io/sbomasm/v2/pkg/logger"
	spdx "github.com/interlynk-io/spdx-zen/model/v3.0.1"
	"github.com/interlynk-io/spdx-zen/parse"
)

func RemoveAuthorFromMetadata(ctx context.Context, doc *parse.Document, targets []interface{}) error {
	log := logger.FromContext(ctx)
	if doc.CreationInfo == nil || len(doc.CreationInfo.CreatedBy) == 0 {
		return nil
	}

	toRemove := make(map[string]bool)
	for _, t := range targets {
		entry, ok := t.(PersonEntry)
		if ok {
			toRemove[entry.SpdxID] = true
		}
	}

	var filtered []spdx.Agent
	for _, agent := range doc.CreationInfo.CreatedBy {
		if !toRemove[agent.SpdxID] {
			filtered = append(filtered, agent)
		}
	}

	removedCount := len(doc.CreationInfo.CreatedBy) - len(filtered)
	doc.CreationInfo.CreatedBy = filtered
	log.Debugf("Removed %d SPDX 3.0 author(s) from CreationInfo", removedCount)

	// Clean up orphaned Person elements
	var removedSpdxIDs []string
	for id := range toRemove {
		removedSpdxIDs = append(removedSpdxIDs, id)
	}
	CleanupOrphanedElements(ctx, doc, removedSpdxIDs)
	return nil
}

func RemoveSupplierFromMetadata(ctx context.Context, doc *parse.Document, targets []interface{}) error {
	log := logger.FromContext(ctx)
	if doc.CreationInfo == nil || len(doc.CreationInfo.CreatedBy) == 0 {
		return nil
	}

	toRemove := make(map[string]bool)
	for _, t := range targets {
		entry, ok := t.(OrgEntry)
		if ok {
			toRemove[entry.SpdxID] = true
		}
	}

	var filtered []spdx.Agent
	for _, agent := range doc.CreationInfo.CreatedBy {
		if !toRemove[agent.SpdxID] {
			filtered = append(filtered, agent)
		}
	}

	removedCount := len(doc.CreationInfo.CreatedBy) - len(filtered)
	doc.CreationInfo.CreatedBy = filtered
	log.Debugf("Removed %d SPDX 3.0 supplier(s) from CreationInfo", removedCount)

	// Clean up orphaned Organization elements
	var removedSpdxIDs []string
	for id := range toRemove {
		removedSpdxIDs = append(removedSpdxIDs, id)
	}
	CleanupOrphanedElements(ctx, doc, removedSpdxIDs)
	return nil
}

func RemoveToolFromMetadata(ctx context.Context, doc *parse.Document, targets []interface{}) error {
	log := logger.FromContext(ctx)
	if doc.CreationInfo == nil || len(doc.CreationInfo.CreatedUsing) == 0 {
		return nil
	}

	toRemove := make(map[string]bool)
	for _, t := range targets {
		entry, ok := t.(ToolEntry)
		if ok {
			toRemove[entry.SpdxID] = true
		}
	}

	var filtered []spdx.Tool
	for _, tool := range doc.CreationInfo.CreatedUsing {
		if !toRemove[tool.SpdxID] {
			filtered = append(filtered, tool)
		}
	}

	removedCount := len(doc.CreationInfo.CreatedUsing) - len(filtered)
	doc.CreationInfo.CreatedUsing = filtered
	log.Debugf("Removed %d SPDX 3.0 tool(s) from CreationInfo", removedCount)

	// Clean up orphaned Tool elements
	var removedSpdxIDs []string
	for id := range toRemove {
		removedSpdxIDs = append(removedSpdxIDs, id)
	}
	CleanupOrphanedElements(ctx, doc, removedSpdxIDs)
	return nil
}

func RemoveTimestampFromMetadata(ctx context.Context, doc *parse.Document, targets []interface{}) error {
	log := logger.FromContext(ctx)
	if doc.CreationInfo == nil {
		return nil
	}

	log.Debugf("Removed SPDX 3.0 document creation timestamp")
	doc.CreationInfo.Created = time.Time{}
	return nil
}

func RemoveLicenseFromMetadata(ctx context.Context, doc *parse.Document, targets []interface{}) error {
	log := logger.FromContext(ctx)
	if doc.SpdxDocument == nil || doc.SpdxDocument.DataLicense == nil {
		return nil
	}

	log.Debugf("Removed SPDX 3.0 document-level DataLicense")
	doc.SpdxDocument.DataLicense = nil
	return nil
}
