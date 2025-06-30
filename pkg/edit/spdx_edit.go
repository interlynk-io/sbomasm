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

package edit

import (
	"fmt"
	"strings"

	"github.com/interlynk-io/sbomasm/internal/version"
	"github.com/interlynk-io/sbomasm/pkg/logger"
	"github.com/samber/lo"
	"github.com/spdx/tools-golang/spdx"
)

const (
	SBOMASM               = "sbomasm"
	SupplierPrefixComment = "The supplier of this document are "
)

var SBOMASM_VERSION = version.Version

type spdxEditDoc struct {
	bom *spdx.Document
	pkg *spdx.Package
	c   *configParams
}

func NewSpdxEditDoc(bom *spdx.Document, c *configParams) (*spdxEditDoc, error) {
	doc := &spdxEditDoc{}

	doc.bom = bom
	doc.c = c

	if c.search.subject == "primary-component" {
		pkg, err := spdxFindPkg(bom, c, true)
		if err == nil {
			doc.pkg = pkg
		}
		if doc.pkg == nil {
			return nil, fmt.Errorf("primary package is missing")
		}
	}

	if c.search.subject == "component-name-version" {

		pkg, err := spdxFindPkg(bom, c, false)
		if err == nil {
			doc.pkg = pkg
		}
		if doc.pkg == nil {
			return nil, fmt.Errorf("package is missing")
		}
	}
	return doc, nil
}

func (d *spdxEditDoc) update() {
	log := logger.FromContext(*d.c.ctx)
	log.Debug("SPDX updating sbom")

	updateFuncs := []struct {
		name string
		f    func() error
	}{
		{"name", d.name},
		{"version", d.version},
		{"supplier", d.supplier},
		{"authors", d.authors},
		{"purl", d.purl},
		{"cpe", d.cpe},
		{"licenses", d.licenses},
		{"hashes", d.hashes},
		{"tools", d.tools},
		{"copyright", d.copyright},
		{"lifeCycles", d.lifeCycles},
		{"description", d.description},
		{"repository", d.repository},
		{"type", d.typ},
		{"timeStamp", d.timeStamp},
	}

	for _, item := range updateFuncs {
		if err := item.f(); err != nil {
			if err == errNotSupported {
				log.Infof(fmt.Sprintf("SPDX error updating %s: %s", item.name, err))
			}
		}
	}
}

func (d *spdxEditDoc) name() error {
	if !d.c.shouldName() {
		return errNoConfiguration
	}

	if d.c.search.subject == "document" {
		return errNotSupported
	}

	if d.c.onMissing() {
		if d.pkg.PackageName == "" {
			d.pkg.PackageName = d.c.name
		}
	} else {
		d.pkg.PackageName = d.c.name
	}

	return nil
}

func (d *spdxEditDoc) version() error {
	if !d.c.shouldVersion() {
		return errNoConfiguration
	}

	if d.c.search.subject == "document" {
		return errNotSupported
	}

	if d.c.onMissing() {
		if d.pkg.PackageVersion == "" {
			d.pkg.PackageVersion = d.c.version
		}
	} else {
		d.pkg.PackageVersion = d.c.version
	}
	return nil
}

func (d *spdxEditDoc) supplier() error {
	if !d.c.shouldSupplier() {
		return errNoConfiguration
	}

	comment := ""
	comment += fmt.Sprintf("%s (%s)", d.c.supplier.name, d.c.supplier.value)

	if d.c.search.subject == "document" {
		// add creator comment
		if d.bom.CreationInfo == nil {
			d.bom.CreationInfo = &spdx.CreationInfo{
				CreatorComment: SupplierPrefixComment + comment,
			}
		} else {
			if d.bom.CreationInfo.CreatorComment == "" {
				d.bom.CreationInfo.CreatorComment = SupplierPrefixComment + comment
			} else {
				if !strings.Contains(d.bom.CreationInfo.CreatorComment, SupplierPrefixComment) {
					d.bom.CreationInfo.CreatorComment += fmt.Sprintf("\n\n"+SupplierPrefixComment+"%s", comment)
				} else {
					d.bom.CreationInfo.CreatorComment += fmt.Sprintf(", "+"%s", comment)
				}
			}
		}
		return nil
	}

	supplier := spdx.Supplier{
		SupplierType: "Organization",
		Supplier:     fmt.Sprintf("%s (%s)", d.c.supplier.name, d.c.supplier.value),
	}

	if d.c.onMissing() {
		if d.pkg.PackageSupplier == nil {
			d.pkg.PackageSupplier = &supplier
		}
	} else {
		d.pkg.PackageSupplier = &supplier
	}

	return nil
}

func (d *spdxEditDoc) authors() error {
	if !d.c.shouldAuthors() {
		return errNoConfiguration
	}

	if d.c.search.subject != "document" {
		return errNotSupported
	}

	authors := []spdx.Creator{}

	for _, author := range d.c.authors {
		authors = append(authors, spdx.Creator{
			CreatorType: "Person",
			Creator:     fmt.Sprintf("%s (%s)", author.name, author.value),
		})
	}

	if d.c.onMissing() {
		if d.bom.CreationInfo == nil {
			d.bom.CreationInfo = &spdx.CreationInfo{
				Creators: authors,
			}
		} else if d.bom.CreationInfo.Creators == nil {
			d.bom.CreationInfo.Creators = authors
		}
	} else if d.c.onAppend() {
		if d.bom.CreationInfo == nil {
			d.bom.CreationInfo = &spdx.CreationInfo{
				Creators: authors,
			}
		} else if d.bom.CreationInfo.Creators == nil {
			d.bom.CreationInfo.Creators = authors
		} else {
			d.bom.CreationInfo.Creators = append(d.bom.CreationInfo.Creators, authors...)
		}
	} else {
		if d.bom.CreationInfo == nil {
			d.bom.CreationInfo = &spdx.CreationInfo{
				Creators: authors,
			}
		} else {
			d.bom.CreationInfo.Creators = authors
		}
	}
	return nil
}

func (d *spdxEditDoc) purl() error {
	if !d.c.shouldPurl() {
		return errNoConfiguration
	}

	if d.c.search.subject == "document" {
		return errNotSupported
	}

	purl := spdx.PackageExternalReference{
		Category: "PACKAGE-MANAGER",
		RefType:  "purl",
		Locator:  d.c.purl,
	}

	foundPurlWithKeyAndValue := false
	for _, ref := range d.pkg.PackageExternalReferences {
		if ref.RefType == "purl" && ref.Locator == d.c.purl {
			foundPurlWithKeyAndValue = true
		}
	}

	if d.c.onMissing() {
		if !foundPurlWithKeyAndValue {
			if d.pkg.PackageExternalReferences == nil {
				d.pkg.PackageExternalReferences = []*spdx.PackageExternalReference{}
			}
			d.pkg.PackageExternalReferences = append(d.pkg.PackageExternalReferences, &purl)
		}
	} else if d.c.onAppend() {
		if !foundPurlWithKeyAndValue {
			if d.pkg.PackageExternalReferences == nil {
				d.pkg.PackageExternalReferences = []*spdx.PackageExternalReference{}
			}
			d.pkg.PackageExternalReferences = append(d.pkg.PackageExternalReferences, &purl)
		} else {
			d.pkg.PackageExternalReferences = append(d.pkg.PackageExternalReferences, &purl)
		}
	} else {
		if d.pkg.PackageExternalReferences == nil {
			d.pkg.PackageExternalReferences = []*spdx.PackageExternalReference{}
			d.pkg.PackageExternalReferences = append(d.pkg.PackageExternalReferences, &purl)
		} else {
			extRef := lo.Reject(d.pkg.PackageExternalReferences, func(x *spdx.PackageExternalReference, _ int) bool {
				return strings.ToLower(x.RefType) == "purl"
			})

			if extRef == nil {
				extRef = []*spdx.PackageExternalReference{}
			}

			d.pkg.PackageExternalReferences = append(extRef, &purl)
		}
	}
	return nil
}

func (d *spdxEditDoc) cpe() error {
	if !d.c.shouldCpe() {
		return errNoConfiguration
	}

	if d.c.search.subject == "document" {
		return errNotSupported
	}

	cpe := spdx.PackageExternalReference{
		Category: "SECURITY",
		RefType:  "cpe23Type",
		Locator:  d.c.cpe,
	}

	foundCpe := false
	for _, ref := range d.pkg.PackageExternalReferences {
		if ref.RefType == "cpe23Type" {
			foundCpe = true
		}
	}

	if d.c.onMissing() {
		if !foundCpe {
			if d.pkg.PackageExternalReferences == nil {
				d.pkg.PackageExternalReferences = []*spdx.PackageExternalReference{}
			}
			d.pkg.PackageExternalReferences = append(d.pkg.PackageExternalReferences, &cpe)
		}
	} else if d.c.onAppend() {
		if !foundCpe {
			if d.pkg.PackageExternalReferences == nil {
				d.pkg.PackageExternalReferences = []*spdx.PackageExternalReference{}
			}
			d.pkg.PackageExternalReferences = append(d.pkg.PackageExternalReferences, &cpe)
		} else {
			d.pkg.PackageExternalReferences = append(d.pkg.PackageExternalReferences, &cpe)
		}
	} else {
		if d.pkg.PackageExternalReferences == nil {
			d.pkg.PackageExternalReferences = []*spdx.PackageExternalReference{}
			d.pkg.PackageExternalReferences = append(d.pkg.PackageExternalReferences, &cpe)
		} else {
			extRef := lo.Reject(d.pkg.PackageExternalReferences, func(x *spdx.PackageExternalReference, _ int) bool {
				return strings.ToLower(x.RefType) == "cpe23type"
			})

			if extRef == nil {
				extRef = []*spdx.PackageExternalReference{}
			}

			d.pkg.PackageExternalReferences = append(extRef, &cpe)
		}
	}
	return nil
}

func (d *spdxEditDoc) licenses() error {
	if !d.c.shouldLicenses() {
		return errNoConfiguration
	}

	license := spdxConstructLicenses(d.bom, d.c)

	if d.c.onMissing() {
		if d.c.search.subject == "document" {
			if d.bom.DataLicense == "" {
				d.bom.DataLicense = license
			}
		} else {
			if d.pkg.PackageLicenseConcluded == "" {
				d.pkg.PackageLicenseConcluded = license
			}
		}
	} else {
		if d.c.search.subject == "document" {
			d.bom.DataLicense = license
		} else {
			d.pkg.PackageLicenseConcluded = license
		}
	}
	return nil
}

func (d *spdxEditDoc) hashes() error {
	if !d.c.shouldHashes() {
		return errNoConfiguration
	}

	if d.c.search.subject == "document" {
		return errNotSupported
	}

	hashes := spdxConstructHashes(d.bom, d.c)

	if d.c.onMissing() {
		if d.pkg.PackageChecksums == nil {
			d.pkg.PackageChecksums = hashes
		}
	} else if d.c.onAppend() {
		if d.pkg.PackageChecksums == nil {
			d.pkg.PackageChecksums = hashes
		} else {
			d.pkg.PackageChecksums = append(d.pkg.PackageChecksums, hashes...)
		}
	} else {
		d.pkg.PackageChecksums = hashes
	}

	return nil
}

func (d *spdxEditDoc) tools() error {
	// default sbomasm tool
	sbomasmTool := spdx.Creator{
		Creator:     fmt.Sprintf("%s-%s", SBOMASM, SBOMASM_VERSION),
		CreatorType: "Tool",
	}

	if d.bom.CreationInfo == nil {
		d.bom.CreationInfo = &spdx.CreationInfo{}
	}

	if d.bom.CreationInfo.Creators == nil {
		d.bom.CreationInfo.Creators = []spdx.Creator{}
	}

	newTools := spdxConstructTools(d.bom, d.c)

	explicitSbomasm := false
	for _, tool := range newTools {
		if strings.HasPrefix(tool.Creator, SBOMASM) {
			sbomasmTool = tool
			explicitSbomasm = true
			break
		}
	}

	if explicitSbomasm {
		d.bom.CreationInfo.Creators = removeCreator(d.bom.CreationInfo.Creators, SBOMASM)
	}

	if d.c.onMissing() {
		for _, tool := range newTools {
			if !creatorExists(d.bom.CreationInfo.Creators, tool) {
				d.bom.CreationInfo.Creators = spdxUniqueCreators(d.bom.CreationInfo.Creators, []spdx.Creator{tool})
			}
		}
		if !creatorExists(d.bom.CreationInfo.Creators, sbomasmTool) {
			d.bom.CreationInfo.Creators = spdxUniqueCreators(d.bom.CreationInfo.Creators, []spdx.Creator{sbomasmTool})
		}
		return nil
	}

	if d.c.onAppend() {
		d.bom.CreationInfo.Creators = spdxUniqueCreators(d.bom.CreationInfo.Creators, newTools)
		if !creatorExists(d.bom.CreationInfo.Creators, sbomasmTool) {
			d.bom.CreationInfo.Creators = spdxUniqueCreators(d.bom.CreationInfo.Creators, []spdx.Creator{sbomasmTool})
		}
		return nil
	}

	d.bom.CreationInfo.Creators = spdxUniqueCreators(d.bom.CreationInfo.Creators, newTools)
	if !creatorExists(d.bom.CreationInfo.Creators, sbomasmTool) {
		d.bom.CreationInfo.Creators = spdxUniqueCreators(d.bom.CreationInfo.Creators, []spdx.Creator{sbomasmTool})
	}

	return nil
}

// remove a creator by name
func removeCreator(creators []spdx.Creator, creatorName string) []spdx.Creator {
	result := []spdx.Creator{}
	for _, c := range creators {
		if !strings.HasPrefix(c.Creator, creatorName) {
			result = append(result, c)
		}
	}
	return result
}

// ensure no duplicate creator
func creatorExists(creators []spdx.Creator, creator spdx.Creator) bool {
	for _, c := range creators {
		if c.Creator == creator.Creator && c.CreatorType == creator.CreatorType {
			return true
		}
	}
	return false
}

// ensure unique creators
func spdxUniqueCreators(existing, newCreators []spdx.Creator) []spdx.Creator {
	creatorSet := make(map[string]struct{})
	for _, c := range existing {
		creatorSet[c.Creator] = struct{}{}
	}
	for _, c := range newCreators {
		if _, exists := creatorSet[c.Creator]; !exists {
			existing = append(existing, c)
		}
	}
	return existing
}

func (d *spdxEditDoc) copyright() error {
	if !d.c.shouldCopyRight() {
		return errNoConfiguration
	}

	if d.c.search.subject == "document" {
		return errNotSupported
	}

	if d.c.onMissing() {
		if d.pkg.PackageCopyrightText == "" {
			d.pkg.PackageCopyrightText = d.c.copyright
		}
	} else {
		d.pkg.PackageCopyrightText = d.c.copyright
	}

	return nil
}

func (d *spdxEditDoc) description() error {
	if !d.c.shouldDescription() {
		return errNoConfiguration
	}

	if d.c.onMissing() {
		if d.c.search.subject == "document" {
			if d.bom.DocumentComment == "" {
				d.bom.DocumentComment = d.c.description
			}
		} else {
			if d.pkg.PackageDescription == "" {
				d.pkg.PackageDescription = d.c.description
			}
		}
	} else {
		if d.c.search.subject == "document" {
			d.bom.DocumentComment = d.c.description
		} else {
			d.pkg.PackageDescription = d.c.description
		}
	}

	return nil
}

func (d *spdxEditDoc) repository() error {
	if !d.c.shouldRepository() {
		return errNoConfiguration
	}

	if d.c.search.subject == "document" {
		return errNotSupported
	}

	if d.c.onMissing() {
		if d.pkg.PackageDownloadLocation == "" {
			d.pkg.PackageDownloadLocation = d.c.repository
		}
	} else {
		d.pkg.PackageDownloadLocation = d.c.repository
	}

	return nil
}

func (d *spdxEditDoc) typ() error {
	if !d.c.shouldTyp() {
		return errNoConfiguration
	}

	if d.c.search.subject == "document" {
		return errNotSupported
	}

	purpose := spdx_strings_to_types[strings.ToLower(d.c.typ)]

	if purpose == "" {
		return errInvalidInput
	}

	if d.c.onMissing() {
		if d.pkg.PrimaryPackagePurpose == "" {
			d.pkg.PrimaryPackagePurpose = purpose
		}
	} else {
		d.pkg.PrimaryPackagePurpose = purpose
	}

	return nil
}

func (d *spdxEditDoc) timeStamp() error {
	if d.c.shouldTimeStamp() {
		return errNoConfiguration
	}

	if d.bom.CreationInfo == nil {
		d.bom.CreationInfo = &spdx.CreationInfo{}
	}
	d.bom.CreationInfo.Created = utcNowTime()

	return nil
}

func (d *spdxEditDoc) lifeCycles() error {
	if !d.c.shouldLifeCycle() {
		return errNoConfiguration
	}

	if d.c.search.subject != "document" {
		return errNotSupported
	}

	lifecycles := fmt.Sprintf("lifecycle: %s", strings.Join(d.c.lifecycles, ","))

	if d.c.onMissing() {
		if d.bom.CreationInfo == nil {
			d.bom.CreationInfo = &spdx.CreationInfo{}
		}
		if d.bom.CreationInfo.CreatorComment == "" {
			d.bom.CreationInfo.CreatorComment = lifecycles
		}
	} else {
		if d.bom.CreationInfo == nil {
			d.bom.CreationInfo = &spdx.CreationInfo{}
		}
		d.bom.CreationInfo.CreatorComment = lifecycles
	}
	return nil
}
