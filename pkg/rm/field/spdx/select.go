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

	"github.com/interlynk-io/sbomasm/pkg/rm/types"
	"github.com/spdx/tools-golang/spdx"
)

func SelectAuthorFromMetadata(doc *spdx.Document) ([]interface{}, error) {
	if doc == nil || doc.CreationInfo == nil || len(doc.CreationInfo.Creators) == 0 {
		return nil, nil
	}

	fmt.Println("Selecting SPDX authors from CreationInfo:", doc.CreationInfo.Creators)
	var selectAuthors []interface{}
	for _, creator := range doc.CreationInfo.Creators {
		fmt.Println("Checking creator:", creator)
		if creator.CreatorType == "Person" {
			selectAuthors = append(selectAuthors, creator)
		}
	}
	fmt.Println("Selecting SPDX authors from CreationInfo:", selectAuthors)
	return selectAuthors, nil
}

func SelectLicenseFromMetadata(doc *spdx.Document) ([]interface{}, error) {
	if doc.DataLicense == "" {
		return nil, nil
	}
	fmt.Println("Selecting SPDX license from document:", doc.DataLicense)
	return []interface{}{doc.DataLicense}, nil
}

func SelectTimestampFromMetadata(doc *spdx.Document) ([]interface{}, error) {
	if doc.CreationInfo == nil || doc.CreationInfo.Created == "" {
		return nil, nil
	}

	fmt.Println("Selecting SPDX timestamp from CreationInfo:", doc.CreationInfo.Created)
	return []interface{}{doc.CreationInfo.Created}, nil
}

func SelectToolFromMetadata(doc *spdx.Document) ([]interface{}, error) {
	if doc == nil || doc.CreationInfo == nil || len(doc.CreationInfo.Creators) == 0 {
		return nil, nil
	}

	var selectTools []interface{}
	for _, creator := range doc.CreationInfo.Creators {
		if creator.CreatorType == "Tool" {
			selectTools = append(selectTools, creator)
		}
	}

	fmt.Println("Selecting SPDX tools from CreationInfo:", selectTools)
	return selectTools, nil
}

func SelectSupplierFromMetadata(doc *spdx.Document) ([]interface{}, error) {
	if doc == nil || doc.CreationInfo == nil || len(doc.CreationInfo.Creators) == 0 {
		return nil, nil
	}

	var selectSuppliers []interface{}
	for _, creator := range doc.CreationInfo.Creators {
		if creator.CreatorType == "Organization" {
			selectSuppliers = append(selectSuppliers, creator)
		}
	}
	fmt.Println("Selecting SPDX suppliers from CreationInfo:", selectSuppliers)
	return selectSuppliers, nil
}

func SelectLifecycleFromMetadata(doc *spdx.Document) ([]interface{}, error) {
	if doc == nil || doc.CreationInfo == nil {
		return nil, nil
	}

	comment := doc.CreationInfo.CreatorComment
	if strings.HasPrefix(strings.ToLower(comment), "lifecycle:") {
		fmt.Println("Selecting SPDX lifecycle from CreationInfo comment:", comment)
		return []interface{}{comment}, nil
	}

	return nil, nil
}

func SelectRepositoryFromMetadata(doc *spdx.Document) ([]interface{}, error) {
	return nil, nil // SPDX does not have a direct equivalent for repositories in metadata
}

func SelectPurlFromComponent(doc *spdx.Document, params *types.RmParams) ([]interface{}, error) {
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
				// Log: "Selecting PURL from component %s: %v", pkg.PackageName, ref
				selected = append(selected, PurlEntry{Package: pkg, Ref: ref})
			}
		}
	}
	if len(selected) == 0 {
		// Log: "No PURL references found in selected components"
	}
	return selected, nil
}

func SelectAuthorFromComponent(doc *spdx.Document, params *types.RmParams) ([]interface{}, error) {
	var selected []interface{}

	for _, comp := range params.SelectedComponents {
		pkg, ok := comp.(*spdx.Package)
		if !ok {
			continue
		}

		if pkg.PackageOriginator != nil {
			if pkg.PackageOriginator.OriginatorType == "Person" {
				fmt.Println("Selecting author from component:", pkg.PackageOriginator.Originator)
				selected = append(selected, AuthorEntry{Package: pkg, Originator: pkg.PackageOriginator})
			}
		}
	}
	return selected, nil
}

func SelectCopyrightFromComponent(doc *spdx.Document, params *types.RmParams) ([]interface{}, error) {
	var selected []interface{}
	for _, comp := range params.SelectedComponents {
		pkg, ok := comp.(*spdx.Package)
		if !ok {
			continue
		}
		if pkg.PackageCopyrightText != "" {
			fmt.Println("Selecting copyright from component:", pkg.PackageName, pkg.PackageCopyrightText)
			selected = append(selected, CopyrightEntry{Package: pkg, Value: pkg.PackageCopyrightText})
		}
	}
	if len(selected) == 0 {
		fmt.Println("No copyright entries found in selected components")
	}
	return selected, nil
}

func SelectCpeFromComponent(doc *spdx.Document, params *types.RmParams) ([]interface{}, error) {
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
				fmt.Println("Selecting CPE from component:", pkg.PackageName, ref.Locator)
				selected = append(selected, CpeEntry{Package: pkg, Ref: ref})
			}
		}
	}
	if len(selected) == 0 {
		fmt.Println("No CPE entries found in selected components")
	}
	return selected, nil
}

func SelectDescriptionFromComponent(doc *spdx.Document, params *types.RmParams) ([]interface{}, error) {
	var selected []interface{}
	for _, comp := range params.SelectedComponents {
		pkg, ok := comp.(*spdx.Package)
		if !ok {
			continue
		}
		if pkg.PackageDescription != "" {
			fmt.Println("Selecting description from component:", pkg.PackageName, pkg.PackageDescription)
			selected = append(selected, DescriptionEntry{Package: pkg, Value: pkg.PackageDescription})
		}
	}
	if len(selected) == 0 {
		fmt.Println("No description entries found in selected components")
	}
	return selected, nil
}

func SelectHashFromComponent(doc *spdx.Document, params *types.RmParams) ([]interface{}, error) {
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
			fmt.Println("Selecting hash from component:", pkg.PackageName, checksum.Value)
			selected = append(selected, HashEntry{Package: pkg, Checksum: &checksum})
		}
	}
	if len(selected) == 0 {
		fmt.Println("No hash entries found in selected components")
	}
	return selected, nil
}

func SelectLicenseFromComponent(doc *spdx.Document, params *types.RmParams) ([]interface{}, error) {
	var selected []interface{}
	for _, comp := range params.SelectedComponents {
		pkg, ok := comp.(*spdx.Package)
		if !ok {
			continue
		}
		if pkg.PackageLicenseConcluded != "" {
			fmt.Println("Selecting license from component:", pkg.PackageName, pkg.PackageLicenseConcluded)
			selected = append(selected, LicenseEntry{Package: pkg, Value: pkg.PackageLicenseConcluded})
		}
	}
	if len(selected) == 0 {
		fmt.Println("No license entries found in selected components")
	}
	return selected, nil
}

func SelectRepoFromComponent(doc *spdx.Document, params *types.RmParams) ([]interface{}, error) {
	var selected []interface{}
	for _, comp := range params.SelectedComponents {
		pkg, ok := comp.(*spdx.Package)
		if !ok {
			continue
		}
		if pkg.PackageDownloadLocation != "" {
			fmt.Println("Selecting repository from component:", pkg.PackageName, pkg.PackageDownloadLocation)
			selected = append(selected, RepositoryEntry{Package: pkg, Value: pkg.PackageDownloadLocation})
		}
	}
	if len(selected) == 0 {
		fmt.Println("No repository entries found in selected components")
	}
	return selected, nil
}

func SelectTypeFromComponent(doc *spdx.Document, params *types.RmParams) ([]interface{}, error) {
	var selected []interface{}
	for _, comp := range params.SelectedComponents {
		pkg, ok := comp.(*spdx.Package)
		if !ok {
			continue
		}
		if pkg.PrimaryPackagePurpose != "" {
			fmt.Println("Selecting type from component:", pkg.PackageName, pkg.PrimaryPackagePurpose)
			selected = append(selected, TypeEntry{Package: pkg, Value: pkg.PrimaryPackagePurpose})
		}
	}
	if len(selected) == 0 {
		fmt.Println("No type entries found in selected components")
	}
	return selected, nil
}

func SelectSupplierFromComponent(doc *spdx.Document, params *types.RmParams) ([]interface{}, error) {
	var selected []interface{}
	for _, comp := range params.SelectedComponents {
		pkg, ok := comp.(*spdx.Package)
		if !ok {
			continue
		}
		if pkg.PackageSupplier != nil {
			fmt.Println("Selecting supplier from component:", pkg.PackageName, pkg.PackageSupplier.Supplier)
			selected = append(selected, SupplierEntry{Package: pkg, Supplier: pkg.PackageSupplier})
		}
	}
	if len(selected) == 0 {
		fmt.Println("No supplier entries found in selected components")
	}
	return selected, nil
}
