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
	"context"
	"strings"

	"github.com/interlynk-io/sbomasm/pkg/logger"
	"github.com/interlynk-io/sbomasm/pkg/rm/types"
	"github.com/spdx/tools-golang/spdx"
)

func SelectAuthorFromMetadata(ctx context.Context, doc *spdx.Document) ([]interface{}, error) {
	log := logger.FromContext(ctx)
	if doc == nil || doc.CreationInfo == nil || len(doc.CreationInfo.Creators) == 0 {
		return nil, nil
	}

	var selectAuthors []interface{}
	for _, creator := range doc.CreationInfo.Creators {
		if creator.CreatorType == "Person" {
			selectAuthors = append(selectAuthors, creator)
		}
	}
	log.Debugf("Selecting SPDX authors from CreationInfo: %v", selectAuthors)
	return selectAuthors, nil
}

func SelectLicenseFromMetadata(ctx context.Context, doc *spdx.Document) ([]interface{}, error) {
	log := logger.FromContext(ctx)
	if doc.DataLicense == "" {
		return nil, nil
	}
	log.Debugf("Selecting SPDX license from document: %s", doc.DataLicense)
	return []interface{}{doc.DataLicense}, nil
}

func SelectTimestampFromMetadata(ctx context.Context, doc *spdx.Document) ([]interface{}, error) {
	log := logger.FromContext(ctx)
	if doc.CreationInfo == nil || doc.CreationInfo.Created == "" {
		return nil, nil
	}

	log.Debugf("Selecting SPDX timestamp from CreationInfo: %s", doc.CreationInfo.Created)
	return []interface{}{doc.CreationInfo.Created}, nil
}

func SelectToolFromMetadata(ctx context.Context, doc *spdx.Document) ([]interface{}, error) {
	log := logger.FromContext(ctx)
	if doc == nil || doc.CreationInfo == nil || len(doc.CreationInfo.Creators) == 0 {
		return nil, nil
	}

	var selectTools []interface{}
	for _, creator := range doc.CreationInfo.Creators {
		if creator.CreatorType == "Tool" {
			selectTools = append(selectTools, creator)
		}
	}

	log.Debugf("Selecting SPDX tools from CreationInfo: %v", selectTools)
	return selectTools, nil
}

func SelectSupplierFromMetadata(ctx context.Context, doc *spdx.Document) ([]interface{}, error) {
	log := logger.FromContext(ctx)
	if doc == nil || doc.CreationInfo == nil || len(doc.CreationInfo.Creators) == 0 {
		return nil, nil
	}

	var selectSuppliers []interface{}
	for _, creator := range doc.CreationInfo.Creators {
		if creator.CreatorType == "Organization" {
			selectSuppliers = append(selectSuppliers, creator)
		}
	}
	log.Debugf("Selecting SPDX suppliers from CreationInfo: %v", selectSuppliers)
	return selectSuppliers, nil
}

func SelectLifecycleFromMetadata(ctx context.Context, doc *spdx.Document) ([]interface{}, error) {
	log := logger.FromContext(ctx)
	if doc == nil || doc.CreationInfo == nil {
		return nil, nil
	}

	comment := doc.CreationInfo.CreatorComment
	if strings.HasPrefix(strings.ToLower(comment), "lifecycle:") {
		log.Debugf("Selecting SPDX lifecycle from CreationInfo comment: %s", comment)
		return []interface{}{comment}, nil
	}

	return nil, nil
}

func SelectRepositoryFromMetadata(ctx context.Context, doc *spdx.Document) ([]interface{}, error) {
	log := logger.FromContext(ctx)
	log.Debugf("Selecting SPDX repository from SPDX metadata is not implemented")
	return nil, nil // SPDX does not have a direct equivalent for repositories in metadata
}

func SelectPurlFromComponent(doc *spdx.Document, params *types.RmParams) ([]interface{}, error) {
	log := logger.FromContext(*params.Ctx)

	var selected []interface{}
	for _, pkg := range params.SelectedComponents {
		pkg, ok := pkg.(*spdx.Package)
		if !ok {
			continue
		}
		if pkg.PackageExternalReferences == nil {
			continue
		}
		for _, ref := range pkg.PackageExternalReferences {
			if ref.RefType == "purl" {
				selected = append(selected, PurlEntry{Package: pkg, Ref: ref})
			}
		}
	}
	if len(selected) == 0 {
		log.Debugf("No PURL references found in selected components")
	}
	log.Debugf("Selected %d PURL entries from components", len(selected))
	return selected, nil
}

func SelectAuthorFromComponent(doc *spdx.Document, params *types.RmParams) ([]interface{}, error) {
	var selected []interface{}
	log := logger.FromContext(*params.Ctx)

	for _, comp := range params.SelectedComponents {
		pkg, ok := comp.(*spdx.Package)
		if !ok {
			continue
		}

		if pkg.PackageOriginator != nil {
			if pkg.PackageOriginator.OriginatorType == "Person" {
				selected = append(selected, AuthorEntry{Package: pkg, Originator: pkg.PackageOriginator})
			}
		}
	}
	log.Debugf("Selected %d author entries from components", len(selected))
	return selected, nil
}

func SelectCopyrightFromComponent(doc *spdx.Document, params *types.RmParams) ([]interface{}, error) {
	log := logger.FromContext(*params.Ctx)
	var selected []interface{}
	for _, comp := range params.SelectedComponents {
		pkg, ok := comp.(*spdx.Package)
		if !ok {
			continue
		}
		if pkg.PackageCopyrightText != "" {
			selected = append(selected, CopyrightEntry{Package: pkg, Value: pkg.PackageCopyrightText})
		}
	}
	if len(selected) == 0 {
		log.Debugf("No copyright entries found in selected components")
	}
	log.Debugf("Selected %d copyright entries from components", len(selected))
	return selected, nil
}

func SelectCpeFromComponent(doc *spdx.Document, params *types.RmParams) ([]interface{}, error) {
	log := logger.FromContext(*params.Ctx)
	var selected []interface{}
	for _, comp := range params.SelectedComponents {
		pkg, ok := comp.(*spdx.Package)
		if !ok {
			continue
		}
		if pkg.PackageExternalReferences == nil {
			continue
		}
		for _, ref := range pkg.PackageExternalReferences {
			if ref.RefType == "cpe22Type" || ref.RefType == "cpe23Type" {
				selected = append(selected, CpeEntry{Package: pkg, Ref: ref})
			}
		}
	}
	if len(selected) == 0 {
		log.Debugf("No CPE entries found in selected components")
	}
	log.Debugf("Selected %d CPE entries from components", len(selected))
	return selected, nil
}

func SelectDescriptionFromComponent(doc *spdx.Document, params *types.RmParams) ([]interface{}, error) {
	log := logger.FromContext(*params.Ctx)
	var selected []interface{}
	for _, comp := range params.SelectedComponents {
		pkg, ok := comp.(*spdx.Package)
		if !ok {
			continue
		}
		if pkg.PackageDescription != "" {
			selected = append(selected, DescriptionEntry{Package: pkg, Value: pkg.PackageDescription})
		}
	}
	if len(selected) == 0 {
		log.Debugf("No description entries found in selected components")
	}
	log.Debugf("Selected %d description entries from components", len(selected))
	return selected, nil
}

func SelectHashFromComponent(doc *spdx.Document, params *types.RmParams) ([]interface{}, error) {
	log := logger.FromContext(*params.Ctx)
	var selected []interface{}
	for _, comp := range params.SelectedComponents {
		pkg, ok := comp.(*spdx.Package)
		if !ok {
			continue
		}
		if pkg.PackageChecksums == nil {
			continue
		}
		for _, checksum := range pkg.PackageChecksums {
			selected = append(selected, HashEntry{Package: pkg, Checksum: &checksum})
		}
	}
	if len(selected) == 0 {
		log.Debugf("No hash entries found in selected components")
	}
	log.Debugf("Selected %d hash entries from components", len(selected))
	return selected, nil
}

func SelectLicenseFromComponent(doc *spdx.Document, params *types.RmParams) ([]interface{}, error) {
	log := logger.FromContext(*params.Ctx)
	var selected []interface{}
	for _, comp := range params.SelectedComponents {
		pkg, ok := comp.(*spdx.Package)
		if !ok {
			continue
		}
		if pkg.PackageLicenseConcluded != "" {
			selected = append(selected, LicenseEntry{Package: pkg, Value: pkg.PackageLicenseConcluded})
		}
	}
	if len(selected) == 0 {
		log.Debugf("No license entries found in selected components")
	}
	log.Debugf("Selected %d license entries from components", len(selected))
	return selected, nil
}

func SelectRepoFromComponent(doc *spdx.Document, params *types.RmParams) ([]interface{}, error) {
	log := logger.FromContext(*params.Ctx)
	var selected []interface{}
	for _, comp := range params.SelectedComponents {
		pkg, ok := comp.(*spdx.Package)
		if !ok {
			continue
		}
		if pkg.PackageDownloadLocation != "" {
			selected = append(selected, RepositoryEntry{Package: pkg, Value: pkg.PackageDownloadLocation})
		}
	}
	if len(selected) == 0 {
		log.Debugf("No repository entries found in selected components")
	}
	log.Debugf("Selected %d repository entries from components", len(selected))
	return selected, nil
}

func SelectTypeFromComponent(doc *spdx.Document, params *types.RmParams) ([]interface{}, error) {
	log := logger.FromContext(*params.Ctx)
	var selected []interface{}
	for _, comp := range params.SelectedComponents {
		pkg, ok := comp.(*spdx.Package)
		if !ok {
			continue
		}
		if pkg.PrimaryPackagePurpose != "" {
			selected = append(selected, TypeEntry{Package: pkg, Value: pkg.PrimaryPackagePurpose})
		}
	}
	if len(selected) == 0 {
		log.Debugf("No type entries found in selected components")
	}
	log.Debugf("Selected %d type entries from components", len(selected))
	return selected, nil
}

func SelectSupplierFromComponent(doc *spdx.Document, params *types.RmParams) ([]interface{}, error) {
	log := logger.FromContext(*params.Ctx)
	var selected []interface{}
	for _, comp := range params.SelectedComponents {
		pkg, ok := comp.(*spdx.Package)
		if !ok {
			continue
		}
		if pkg.PackageSupplier != nil {
			selected = append(selected, SupplierEntry{Package: pkg, Supplier: pkg.PackageSupplier})
		}
	}
	if len(selected) == 0 {
		log.Debugf("No supplier entries found in selected components")
	}
	log.Debugf("Selected %d supplier entries from components", len(selected))
	return selected, nil
}
