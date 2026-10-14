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
	"strings"

	"github.com/interlynk-io/sbomasm/v2/pkg/logger"
	"github.com/interlynk-io/sbomasm/v2/pkg/rm/types"
	spdx "github.com/interlynk-io/spdx-zen/model/v3.0.1"
	"github.com/interlynk-io/spdx-zen/parse"
)

func RemoveHashFromComponent(doc *parse.Document, targets []interface{}, params *types.RmParams) error {
	log := logger.FromContext(*params.Ctx)

	for _, entry := range targets {
		e, ok := entry.(ComponentHashEntry)
		if !ok {
			continue
		}
		pkg := e.Component
		var filtered []interface{}
		for _, vu := range pkg.VerifiedUsing {
			var algo spdx.HashAlgorithm
			if hash, ok := vu.(*spdx.Hash); ok {
				algo = hash.Algorithm
			} else if hash, ok := vu.(spdx.Hash); ok {
				algo = hash.Algorithm
			}
			if algo == e.Hash.Algorithm {
				continue
			}
			filtered = append(filtered, vu)
		}
		pkg.VerifiedUsing = filtered
		log.Debugf("Removed hash %s from component %s", e.Hash.Algorithm, pkg.SpdxID)
	}

	return nil
}

func RemovePurlFromComponent(doc *parse.Document, targets []interface{}, params *types.RmParams) error {
	log := logger.FromContext(*params.Ctx)

	// Group targets by component SpdxID
	byComponent := make(map[string][]ComponentExternalIdentifierEntry)
	for _, entry := range targets {
		e, ok := entry.(ComponentExternalIdentifierEntry)
		if !ok {
			continue
		}
		key := e.Component.SpdxID
		byComponent[key] = append(byComponent[key], e)
	}

	for _, entry := range targets {
		e, ok := entry.(ComponentExternalIdentifierEntry)
		if !ok {
			continue
		}
		pkg := e.Component
		key := pkg.SpdxID
		if len(byComponent[key]) == 0 {
			continue
		}

		// Build a set of identifiers to remove
		toRemove := make(map[string]bool)
		for _, t := range byComponent[key] {
			toRemove[t.ExtId.Identifier] = true
		}

		var filtered []spdx.ExternalIdentifier
		for _, ext := range pkg.ExternalIdentifier {
			if ext.ExternalIdentifierType == spdx.ExternalIdentifierTypePackageUrl && toRemove[ext.Identifier] {
				continue
			}
			filtered = append(filtered, ext)
		}
		pkg.ExternalIdentifier = filtered
		byComponent[key] = nil // mark as done
		log.Debugf("Removed PURL(s) from component %s", pkg.SpdxID)
	}

	return nil
}

func RemoveCpeFromComponent(doc *parse.Document, targets []interface{}, params *types.RmParams) error {
	log := logger.FromContext(*params.Ctx)

	// Group targets by component SpdxID
	byComponent := make(map[string][]ComponentExternalIdentifierEntry)
	for _, entry := range targets {
		e, ok := entry.(ComponentExternalIdentifierEntry)
		if !ok {
			continue
		}
		key := e.Component.SpdxID
		byComponent[key] = append(byComponent[key], e)
	}

	for _, entry := range targets {
		e, ok := entry.(ComponentExternalIdentifierEntry)
		if !ok {
			continue
		}
		pkg := e.Component
		key := pkg.SpdxID
		if len(byComponent[key]) == 0 {
			continue
		}

		// Build a set of identifiers to remove
		toRemove := make(map[string]bool)
		for _, t := range byComponent[key] {
			toRemove[t.ExtId.Identifier] = true
		}

		var filtered []spdx.ExternalIdentifier
		for _, ext := range pkg.ExternalIdentifier {
			if (ext.ExternalIdentifierType == spdx.ExternalIdentifierTypeCpe22 || ext.ExternalIdentifierType == spdx.ExternalIdentifierTypeCpe23) && toRemove[ext.Identifier] {
				continue
			}
			filtered = append(filtered, ext)
		}
		pkg.ExternalIdentifier = filtered
		byComponent[key] = nil // mark as done
		log.Debugf("Removed CPE(s) from component %s", pkg.SpdxID)
	}

	return nil
}

func RemoveRepoFromComponent(doc *parse.Document, targets []interface{}, params *types.RmParams) error {
	log := logger.FromContext(*params.Ctx)

	// Group targets by component SpdxID
	byComponent := make(map[string][]ComponentExternalRefEntry)
	for _, entry := range targets {
		e, ok := entry.(ComponentExternalRefEntry)
		if !ok {
			continue
		}
		key := e.Component.SpdxID
		byComponent[key] = append(byComponent[key], e)
	}

	for _, entry := range targets {
		e, ok := entry.(ComponentExternalRefEntry)
		if !ok {
			continue
		}
		pkg := e.Component
		key := pkg.SpdxID
		if len(byComponent[key]) == 0 {
			continue
		}

		// Build a set of locators to remove
		toRemove := make(map[string]bool)
		for _, t := range byComponent[key] {
			for _, loc := range t.ExtRef.Locator {
				toRemove[loc] = true
			}
		}

		var filtered []spdx.ExternalRef
		for _, ref := range pkg.ExternalRef {
			if ref.ExternalRefType == spdx.ExternalRefTypeVcs {
				match := false
				for _, loc := range ref.Locator {
					if toRemove[loc] {
						match = true
						break
					}
				}
				if match {
					continue
				}
			}
			filtered = append(filtered, ref)
		}
		pkg.ExternalRef = filtered
		byComponent[key] = nil // mark as done
		log.Debugf("Removed repository from component %s", pkg.SpdxID)
	}

	return nil
}

func RemoveLicenseFromComponent(doc *parse.Document, targets []interface{}, params *types.RmParams) error {
	log := logger.FromContext(*params.Ctx)

	var orphanedLicIDs []string
	for _, entry := range targets {
		e, ok := entry.(ComponentLicenseEntry)
		if !ok {
			continue
		}
		rel := e.Relationship
		pkg := e.Component

		log.Debugf("Removing concluded license from component %s", pkg.SpdxID)

		// Collect license SpdxIDs for orphan cleanup
		for _, to := range rel.To {
			if id := to.GetSpdxID(); id != "" {
				orphanedLicIDs = append(orphanedLicIDs, id)
			}
		}

		// Remove this relationship from the document
		var filtered []*spdx.Relationship
		for _, r := range doc.Relationships {
			if r != rel {
				filtered = append(filtered, r)
			}
		}
		doc.Relationships = filtered
	}

	// Clean up orphaned license elements if no longer referenced
	if len(orphanedLicIDs) > 0 {
		CleanupOrphanedElements(*params.Ctx, doc, orphanedLicIDs)
	}

	return nil
}

func RemoveTypeFromComponent(doc *parse.Document, targets []interface{}, params *types.RmParams) error {
	log := logger.FromContext(*params.Ctx)

	for _, entry := range targets {
		e, ok := entry.(ComponentTypeEntry)
		if !ok {
			continue
		}
		pkg := e.Component

		// Clear all AdditionalPurpose entries and PrimaryPurpose
		pkg.AdditionalPurpose = nil
		pkg.PrimaryPurpose = ""
		log.Debugf("Removed type/purpose from component %s", pkg.SpdxID)
	}

	return nil
}

func RemoveDescriptionFromComponent(doc *parse.Document, targets []interface{}, params *types.RmParams) error {
	log := logger.FromContext(*params.Ctx)

	for _, entry := range targets {
		e, ok := entry.(ComponentDescriptionEntry)
		if !ok {
			continue
		}
		pkg := e.Component
		pkg.Description = ""
		log.Debugf("Removed description from component %s", pkg.SpdxID)
	}

	return nil
}

func RemoveCopyrightFromComponent(doc *parse.Document, targets []interface{}, params *types.RmParams) error {
	log := logger.FromContext(*params.Ctx)

	for _, entry := range targets {
		e, ok := entry.(ComponentCopyrightEntry)
		if !ok {
			continue
		}
		pkg := e.Component
		pkg.CopyrightText = ""
		log.Debugf("Removed copyright from component %s", pkg.SpdxID)
	}

	return nil
}

func RemoveAuthorFromComponent(doc *parse.Document, targets []interface{}, params *types.RmParams) error {
	log := logger.FromContext(*params.Ctx)

	// Group targets by component SpdxID to handle multiple removals safely
	type removal struct {
		spdxID string // SpdxID of the agent to remove
	}
	byComponent := make(map[string][]removal)
	for _, entry := range targets {
		e, ok := entry.(ComponentAuthorEntry)
		if !ok || e.Person == nil {
			continue
		}
		key := e.Component.SpdxID
		byComponent[key] = append(byComponent[key], removal{spdxID: e.Person.SpdxID})
	}

	for _, entry := range targets {
		e, ok := entry.(ComponentAuthorEntry)
		if !ok {
			continue
		}
		pkg := e.Component
		key := pkg.SpdxID
		if _, done := byComponent[key+"_done"]; done {
			continue
		}

		// Build a set of SpdxIDs to remove
		toRemove := make(map[string]bool)
		for _, r := range byComponent[key] {
			toRemove[r.spdxID] = true
		}

		var filtered []spdx.Agent
		for _, agent := range pkg.OriginatedBy {
			if !toRemove[agent.SpdxID] {
				filtered = append(filtered, agent)
			}
		}
		pkg.OriginatedBy = filtered
		byComponent[key+"_done"] = nil // mark as done
		log.Debugf("Removed %d author(s) from component %s", len(byComponent[key]), pkg.SpdxID)
	}

	// Clean up orphaned Person elements
	var removedSpdxIDs []string
	for key := range byComponent {
		if !strings.HasSuffix(key, "_done") {
			for _, r := range byComponent[key] {
				removedSpdxIDs = append(removedSpdxIDs, r.spdxID)
			}
		}
	}
	if len(removedSpdxIDs) > 0 {
		CleanupOrphanedElements(*params.Ctx, doc, removedSpdxIDs)
	}
	return nil
}

func RemoveSupplierFromComponent(doc *parse.Document, targets []interface{}, params *types.RmParams) error {
	log := logger.FromContext(*params.Ctx)

	var removedSpdxIDs []string
	for _, entry := range targets {
		e, ok := entry.(ComponentSupplierEntry)
		if !ok || e.Org == nil {
			continue
		}
		pkg := e.Component
		if pkg.SuppliedBy != nil {
			removedSpdxIDs = append(removedSpdxIDs, pkg.SuppliedBy.SpdxID)
			pkg.SuppliedBy = nil
			log.Debugf("Removed supplier from component %s", pkg.SpdxID)
		}
	}

	// Clean up orphaned Organization elements
	if len(removedSpdxIDs) > 0 {
		CleanupOrphanedElements(*params.Ctx, doc, removedSpdxIDs)
	}
	return nil
}
