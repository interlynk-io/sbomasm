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
	"github.com/interlynk-io/spdx-zen/parse"
)

func SelectAuthorFromMetadata(ctx context.Context, doc *parse.Document) ([]interface{}, error) {
	log := logger.FromContext(ctx)
	if doc.CreationInfo == nil || len(doc.CreationInfo.CreatedBy) == 0 {
		return nil, nil
	}

	var authors []interface{}
	for _, agent := range doc.CreationInfo.CreatedBy {
		spdxID := agent.SpdxID
		if spdxID == "" {
			continue
		}
		if person := doc.GetPersonByID(spdxID); person != nil {
			authors = append(authors, PersonEntry{SpdxID: spdxID, Person: person})
		}
	}

	log.Debugf("Selected %d SPDX 3.0 authors from CreationInfo", len(authors))
	return authors, nil
}

func SelectSupplierFromMetadata(ctx context.Context, doc *parse.Document) ([]interface{}, error) {
	log := logger.FromContext(ctx)
	if doc.CreationInfo == nil || len(doc.CreationInfo.CreatedBy) == 0 {
		return nil, nil
	}

	var suppliers []interface{}
	for _, agent := range doc.CreationInfo.CreatedBy {
		spdxID := agent.SpdxID
		if spdxID == "" {
			continue
		}
		if org := doc.GetOrganizationByID(spdxID); org != nil {
			suppliers = append(suppliers, OrgEntry{SpdxID: spdxID, Organization: org})
		}
	}

	log.Debugf("Selected %d SPDX 3.0 suppliers from CreationInfo", len(suppliers))
	return suppliers, nil
}

func SelectToolFromMetadata(ctx context.Context, doc *parse.Document) ([]interface{}, error) {
	log := logger.FromContext(ctx)
	if doc.CreationInfo == nil || len(doc.CreationInfo.CreatedUsing) == 0 {
		return nil, nil
	}

	var tools []interface{}
	for _, tool := range doc.CreationInfo.CreatedUsing {
		spdxID := tool.SpdxID
		if spdxID == "" {
			continue
		}
		if t := doc.GetToolByID(spdxID); t != nil {
			tools = append(tools, ToolEntry{SpdxID: spdxID, Tool: t})
		}
	}

	log.Debugf("Selected %d SPDX 3.0 tools from CreationInfo", len(tools))
	return tools, nil
}

func SelectTimestampFromMetadata(ctx context.Context, doc *parse.Document) ([]interface{}, error) {
	log := logger.FromContext(ctx)
	if doc.CreationInfo == nil || doc.CreationInfo.Created.IsZero() {
		return nil, nil
	}

	log.Debugf("Selected SPDX 3.0 timestamp from CreationInfo: %s", doc.CreationInfo.Created)
	return []interface{}{doc.CreationInfo.Created}, nil
}

func SelectLicenseFromMetadata(ctx context.Context, doc *parse.Document) ([]interface{}, error) {
	log := logger.FromContext(ctx)
	if doc.SpdxDocument == nil || doc.SpdxDocument.DataLicense == nil {
		return nil, nil
	}

	log.Debugf("Selected SPDX 3.0 document license: %s", doc.SpdxDocument.DataLicense.SpdxID)
	return []interface{}{LicenseEntry{License: doc.SpdxDocument.DataLicense}}, nil
}
