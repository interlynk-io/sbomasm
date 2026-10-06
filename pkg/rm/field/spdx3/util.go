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

	"github.com/interlynk-io/sbomasm/v2/pkg/logger"
	spdx "github.com/interlynk-io/spdx-zen/model/v3.0.1"
	"github.com/interlynk-io/spdx-zen/parse"
)

func isPerson(doc *parse.Document, spdxID string) bool {
	return doc.GetPersonByID(spdxID) != nil
}

func isOrganization(doc *parse.Document, spdxID string) bool {
	return doc.GetOrganizationByID(spdxID) != nil
}

func getAgentName(doc *parse.Document, spdxID string) string {
	if p := doc.GetPersonByID(spdxID); p != nil {
		return p.Name
	}
	if o := doc.GetOrganizationByID(spdxID); o != nil {
		return o.Name
	}
	if t := doc.GetToolByID(spdxID); t != nil {
		return t.Name
	}
	return ""
}

// isReferencedElsewhere checks if an element with the given SpdxID is still
// referenced anywhere in the document (CreationInfo, component fields, etc.)
func isReferencedElsewhere(doc *parse.Document, spdxID string) bool {
	// Check CreationInfo.CreatedBy (Person or Organization)
	if doc.CreationInfo != nil {
		for _, agent := range doc.CreationInfo.CreatedBy {
			if agent.SpdxID == spdxID {
				return true
			}
		}
		for _, tool := range doc.CreationInfo.CreatedUsing {
			if tool.SpdxID == spdxID {
				return true
			}
		}
	}

	// Check all packages' OriginatedBy and SuppliedBy
	for _, pkg := range doc.Packages {
		for _, agent := range pkg.OriginatedBy {
			if agent.SpdxID == spdxID {
				return true
			}
		}
		if pkg.SuppliedBy != nil && pkg.SuppliedBy.SpdxID == spdxID {
			return true
		}
	}

	return false
}

// SyncCreationInfoToAllElements copies the document-level CreationInfo to every
// element in the document. This is necessary because spdx-zen's serializer
// extracts CreationInfo from each element's own struct via reflection, not from
// doc.CreationInfo. Without this sync, modifications to doc.CreationInfo won't
// be reflected in the serialized output.
func SyncCreationInfoToAllElements(doc *parse.Document) {
	if doc.CreationInfo == nil {
		return
	}
	ci := *doc.CreationInfo

	if doc.SpdxDocument != nil {
		doc.SpdxDocument.CreationInfo = ci
	}
	for _, e := range doc.Packages {
		if e != nil {
			e.CreationInfo = ci
		}
	}
	for _, e := range doc.Files {
		if e != nil {
			e.CreationInfo = ci
		}
	}
	for _, e := range doc.Snippets {
		if e != nil {
			e.CreationInfo = ci
		}
	}
	for _, e := range doc.SoftwareArtifacts {
		if e != nil {
			e.CreationInfo = ci
		}
	}
	for _, e := range doc.Relationships {
		if e != nil {
			e.CreationInfo = ci
		}
	}
	for _, e := range doc.LifecycleScopedRelationships {
		if e != nil {
			e.CreationInfo = ci
		}
	}
	for _, e := range doc.Annotations {
		if e != nil {
			e.CreationInfo = ci
		}
	}
	for _, e := range doc.Organizations {
		if e != nil {
			e.CreationInfo = ci
		}
	}
	for _, e := range doc.Persons {
		if e != nil {
			e.CreationInfo = ci
		}
	}
	for _, e := range doc.SoftwareAgents {
		if e != nil {
			e.CreationInfo = ci
		}
	}
	for _, e := range doc.Tools {
		if e != nil {
			e.CreationInfo = ci
		}
	}
	for _, e := range doc.Bundles {
		if e != nil {
			e.CreationInfo = ci
		}
	}
	for _, e := range doc.Boms {
		if e != nil {
			e.CreationInfo = ci
		}
	}
	for _, e := range doc.Sboms {
		if e != nil {
			e.CreationInfo = ci
		}
	}
	for _, e := range doc.AnyLicenseInfos {
		if e != nil {
			e.CreationInfo = ci
		}
	}
	for _, e := range doc.ConjunctiveLicenseSets {
		if e != nil {
			e.CreationInfo = ci
		}
	}
	for _, e := range doc.CustomLicenses {
		if e != nil {
			e.CreationInfo = ci
		}
	}
	for _, e := range doc.CustomLicenseAdditions {
		if e != nil {
			e.CreationInfo = ci
		}
	}
	for _, e := range doc.DisjunctiveLicenseSets {
		if e != nil {
			e.CreationInfo = ci
		}
	}
	for _, e := range doc.IndividualLicensingInfos {
		if e != nil {
			e.CreationInfo = ci
		}
	}
	for _, e := range doc.ListedLicenses {
		if e != nil {
			e.CreationInfo = ci
		}
	}
	for _, e := range doc.ListedLicenseExceptions {
		if e != nil {
			e.CreationInfo = ci
		}
	}
	for _, e := range doc.LicenseExpressions {
		if e != nil {
			e.CreationInfo = ci
		}
	}
	for _, e := range doc.OrLaterOperators {
		if e != nil {
			e.CreationInfo = ci
		}
	}
	for _, e := range doc.SimpleLicensingTexts {
		if e != nil {
			e.CreationInfo = ci
		}
	}
	for _, e := range doc.WithAdditionOperators {
		if e != nil {
			e.CreationInfo = ci
		}
	}
	for _, e := range doc.Vulnerabilities {
		if e != nil {
			e.CreationInfo = ci
		}
	}
	for _, e := range doc.CvssV2VulnAssessments {
		if e != nil {
			e.CreationInfo = ci
		}
	}
	for _, e := range doc.CvssV3VulnAssessments {
		if e != nil {
			e.CreationInfo = ci
		}
	}
	for _, e := range doc.CvssV4VulnAssessments {
		if e != nil {
			e.CreationInfo = ci
		}
	}
	for _, e := range doc.EpssVulnAssessments {
		if e != nil {
			e.CreationInfo = ci
		}
	}
	for _, e := range doc.SsvcVulnAssessments {
		if e != nil {
			e.CreationInfo = ci
		}
	}
	for _, e := range doc.ExploitCatalogVulnAssessments {
		if e != nil {
			e.CreationInfo = ci
		}
	}
	for _, e := range doc.VexAffectedVulnAssessments {
		if e != nil {
			e.CreationInfo = ci
		}
	}
	for _, e := range doc.VexFixedVulnAssessments {
		if e != nil {
			e.CreationInfo = ci
		}
	}
	for _, e := range doc.VexNotAffectedVulnAssessments {
		if e != nil {
			e.CreationInfo = ci
		}
	}
	for _, e := range doc.VexUnderInvestigationVulnAssessments {
		if e != nil {
			e.CreationInfo = ci
		}
	}
	for _, e := range doc.AiPackages {
		if e != nil {
			e.CreationInfo = ci
		}
	}
	for _, e := range doc.DatasetPackages {
		if e != nil {
			e.CreationInfo = ci
		}
	}
	for _, e := range doc.Builds {
		if e != nil {
			e.CreationInfo = ci
		}
	}
}

// CleanupOrphanedElements removes Person, Organization, and Tool elements from
// the document that are no longer referenced by any CreationInfo or component.
// It should be called after removal operations that affect SpdxID references.
func CleanupOrphanedElements(ctx context.Context, doc *parse.Document, candidateSpdxIDs []string) {
	log := logger.FromContext(ctx)

	for _, spdxID := range candidateSpdxIDs {
		if isReferencedElsewhere(doc, spdxID) {
			continue
		}

		// Determine element type and remove from appropriate slice
		switch {
		case isPerson(doc, spdxID):
			var filtered []*spdx.Person
			for _, p := range doc.Persons {
				if p.SpdxID != spdxID {
					filtered = append(filtered, p)
				}
			}
			doc.Persons = filtered
			log.Debugf("Orphaned Person %s removed from document", spdxID)

		case isOrganization(doc, spdxID):
			var filtered []*spdx.Organization
			for _, o := range doc.Organizations {
				if o.SpdxID != spdxID {
					filtered = append(filtered, o)
				}
			}
			doc.Organizations = filtered
			log.Debugf("Orphaned Organization %s removed from document", spdxID)

		case doc.GetToolByID(spdxID) != nil:
			var filtered []*spdx.Tool
			for _, t := range doc.Tools {
				if t.SpdxID != spdxID {
					filtered = append(filtered, t)
				}
			}
			doc.Tools = filtered
			log.Debugf("Orphaned Tool %s removed from document", spdxID)
		}
	}
}
