// Copyright 2023 Interlynk.io
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
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/google/uuid"
	"github.com/interlynk-io/sbomasm/pkg/logger"
	"github.com/samber/lo"
	"github.com/spdx/tools-golang/spdx"
	"github.com/spdx/tools-golang/spdx/v2/common"
	"github.com/spdx/tools-golang/spdx/v2/v2_3"
)

type merge struct {
	settings      *MergeSettings
	out           *spdx.Document
	in            []*spdx.Document
	rootPackageID string
}

func newMerge(ms *MergeSettings) *merge {
	return &merge{
		settings:      ms,
		in:            []*spdx.Document{},
		out:           &spdx.Document{},
		rootPackageID: uuid.New().String(),
	}
}

func (m *merge) loadBoms() {
	for _, path := range m.settings.Input.Files {
		bom, err := loadBom(*m.settings.Ctx, path)
		if err != nil {
			panic(err) // TODO: return error instead of panic
		}
		m.in = append(m.in, bom)
	}
}

func (m *merge) initOutBom() {
	m.out.SPDXVersion = spdx.Version
	m.out.DataLicense = spdx.DataLicense
	m.out.SPDXIdentifier = common.ElementID("DOCUMENT")
	m.out.DocumentName = m.settings.App.Name
	m.out.DocumentNamespace = composeNamespace(m.settings.App.Name)
	m.out.CreationInfo = &v2_3.CreationInfo{}
	m.out.CreationInfo.Created = utcNowTime()

	//Add all creators from the input sboms
	creators := getAllCreators(m.in, m.settings.App.Authors)
	m.out.CreationInfo.Creators = append(m.out.CreationInfo.Creators, creators...)

	version := getLicenseListVersion(m.in)
	if version != "" {
		m.out.CreationInfo.LicenseListVersion = version
	}
	m.out.ExternalDocumentReferences = append(m.out.ExternalDocumentReferences, externalDocumentRefs(m.in)...)
	m.out.CreationInfo.CreatorComment = getCreatorComments(m.in)
}

func (m *merge) setupPrimaryComp() *spdx.Package {
	p := &spdx.Package{}
	p.PackageName = m.settings.App.Name
	p.PackageVersion = m.settings.App.Version
	p.PackageSPDXIdentifier = common.ElementID(fmt.Sprintf("RootPackage-%s", m.rootPackageID))
	p.PackageDownloadLocation = "NOASSERTION"

	if m.settings.App.Supplier.Name != "" || m.settings.App.Supplier.Email != "" {
		p.PackageSupplier = &common.Supplier{}
		p.PackageSupplier.SupplierType = "Organization"
		p.PackageSupplier.Supplier = fmt.Sprintf("%s (%s)", m.settings.App.Supplier.Name, m.settings.App.Supplier.Email)
	} else {
		p.PackageSupplier = &common.Supplier{}
		p.PackageSupplier.SupplierType = "NOASSERTION"
		p.PackageSupplier.Supplier = "NOASSERTION"
	}

	p.FilesAnalyzed = true

	if len(m.settings.App.Checksums) > 0 {
		p.PackageChecksums = []common.Checksum{}
		for _, c := range m.settings.App.Checksums {
			if len(c.Value) == 0 {
				continue
			}
			p.PackageChecksums = append(p.PackageChecksums, common.Checksum{
				Algorithm: spdx_hash_algos[c.Algorithm],
				Value:     c.Value,
			})
		}
	}

	if m.settings.App.License.Id != "" {
		p.PackageLicenseConcluded = m.settings.App.License.Id
	}

	if m.settings.App.License.Expression != "" {
		p.PackageLicenseConcluded = m.settings.App.License.Expression
	}

	if m.settings.App.License.Expression != "" && m.settings.App.License.Id == "" {
		p.PackageLicenseDeclared = "NOASSERTION"
		p.PackageLicenseConcluded = "NOASSERTION"
	}

	if m.settings.App.Copyright != "" {
		p.PackageCopyrightText = m.settings.App.Copyright
	} else {
		p.PackageCopyrightText = "NOASSERTION"
	}

	p.PackageDescription = m.settings.App.Description
	p.PrimaryPackagePurpose = m.settings.App.PrimaryPurpose

	p.PackageExternalReferences = []*spdx.PackageExternalReference{}

	if m.settings.App.Purl != "" {
		purl := spdx.PackageExternalReference{
			Category: common.CategoryPackageManager,
			RefType:  common.TypePackageManagerPURL,
			Locator:  m.settings.App.Purl,
		}
		p.PackageExternalReferences = append(p.PackageExternalReferences, &purl)
	}

	if m.settings.App.CPE != "" {
		cpe := spdx.PackageExternalReference{
			Category: common.CategorySecurity,
			RefType:  common.TypeSecurityCPE23Type,
			Locator:  m.settings.App.CPE,
		}
		p.PackageExternalReferences = append(p.PackageExternalReferences, &cpe)
	}

	return p
}

func (m *merge) isDescribedPackage(pkg *spdx.Package, descRels []*spdx.Relationship) bool {
	if pkg == nil {
		return false
	}

	for _, rel := range descRels {
		if rel == nil {
			continue
		}
		if rel.RefB.ElementRefID == pkg.PackageSPDXIdentifier {
			return true
		}
	}

	return false
}

func (m *merge) hierarchicalMerge() error {
	log := logger.FromContext(*m.settings.Ctx)

	pc := m.setupPrimaryComp()

	log.Debugf("primary component id: %s", pc.PackageSPDXIdentifier)

	pkgs := []*spdx.Package{pc}
	deps := []*spdx.Relationship{}
	files := []*spdx.File{}

	//Add relationship between document and primary package
	deps = append(deps, &spdx.Relationship{
		RefA:         common.MakeDocElementID("", "DOCUMENT"),
		RefB:         common.MakeDocElementID("", string(pc.PackageSPDXIdentifier)),
		Relationship: common.TypeRelationshipDescribe,
	})

	docNames := lo.Map(m.in, func(doc *spdx.Document, _ int) string {
		return doc.DocumentName
	})

	for _, doc := range m.in {
		log.Debugf("processing sbom %s with packages:%d, files:%d, deps:%d, Snips:%d OtherLics:%d, Annotations:%d, externaldocrefs:%d",
			fmt.Sprintf("%s-%s", doc.SPDXIdentifier, doc.DocumentName),
			len(doc.Packages), len(doc.Files), len(doc.Relationships),
			len(doc.Snippets), len(doc.OtherLicenses), len(doc.Annotations),
			len(doc.ExternalDocumentReferences))

		descRels := lo.Filter(doc.Relationships, func(rel *spdx.Relationship, _ int) bool {
			if rel == nil {
				return false
			}
			return rel.Relationship == common.TypeRelationshipDescribe
		})

		newDocPrimaryPackageIdent := common.ElementID(fmt.Sprintf("Package-%s", uuid.New().String()))
		oldDocPrimaryPackageIdent := common.ElementID("")

		for _, pkg := range doc.Packages {
			isDescPkg := m.isDescribedPackage(pkg, descRels)

			cPkg, err := cloneComp(pkg)
			if err != nil {
				log.Warnf("Failed to clone component: %s : %s", pkg.PackageSPDXIdentifier, pkg.PackageName)
				continue
			}

			if isDescPkg {
				//Change the SPDX Identifier to the package specified
				oldDocPrimaryPackageIdent = cPkg.PackageSPDXIdentifier
				cPkg.PackageSPDXIdentifier = newDocPrimaryPackageIdent

				deps = append(deps, &spdx.Relationship{
					RefA:         common.MakeDocElementID("", string(pc.PackageSPDXIdentifier)),
					RefB:         common.MakeDocElementID("", string(cPkg.PackageSPDXIdentifier)),
					Relationship: common.TypeRelationshipContains,
				})
			}

			if !cPkg.FilesAnalyzed {
				cPkg.PackageVerificationCode = nil
			}

			for _, f := range cPkg.Files {
				if f.FileSPDXIdentifier == "" {
					continue
				}
				files = append(files, f)
			}

			cPkg.Files = []*spdx.File{}
			pkgs = append(pkgs, cPkg)
		}

		for _, rel := range doc.Relationships {
			if rel == nil {
				continue
			}

			if rel.RefA.ElementRefID == oldDocPrimaryPackageIdent {
				rel.RefA.ElementRefID = newDocPrimaryPackageIdent
			}

			if rel.RefB.ElementRefID == oldDocPrimaryPackageIdent {
				rel.RefB.ElementRefID = newDocPrimaryPackageIdent
			}

			// if the relationship has a DocumentRef defined, and the
			// document is part of the merge set, we should null it out.

			if rel.RefA.DocumentRefID != "" {
				if lo.Contains(docNames, rel.RefA.DocumentRefID) {
					rel.RefA.DocumentRefID = ""
				}
			}

			if rel.RefB.DocumentRefID != "" {
				if lo.Contains(docNames, rel.RefB.DocumentRefID) {
					rel.RefB.DocumentRefID = ""
				}
			}
			deps = append(deps, rel)
		}
	}

	deps = append(deps, lo.FlatMap(m.in, func(doc *spdx.Document, _ int) []*spdx.Relationship {
		return lo.Filter(doc.Relationships, func(rel *spdx.Relationship, _ int) bool {
			if rel == nil {
				return false
			}
			return rel.Relationship != common.TypeRelationshipDescribe
		})
	})...)

	docFiles := lo.Flatten(lo.Map(m.in, func(pkg *spdx.Document, _ int) []*spdx.File {
		return pkg.Files
	}))

	files = append(files, docFiles...)

	m.out.Packages = pkgs
	m.out.Files = files
	m.out.Relationships = deps
	m.out.OtherLicenses = getOtherLicenses(m.in)

	return m.writeSBOM()
}

func (m *merge) flatMerge() error {
	return fmt.Errorf("not implemented")
}

func (m *merge) assemblyMerge() error {
	return fmt.Errorf("not implemented")
}

func (m *merge) writeSBOM() error {
	log := logger.FromContext(*m.settings.Ctx)
	var f io.Writer
	outName := "stdout"

	if m.settings.Output.File == "" {
		f = os.Stdout
	} else {
		var err error
		outName = m.settings.Output.File
		f, err = os.Create(m.settings.Output.File)
		if err != nil {
			return err
		}
	}

	buf, err := json.MarshalIndent(m.out, "", " ")
	if err != nil {
		return err
	}

	_, err = f.Write(buf)
	if err != nil {
		return err
	}

	log.Debugf("wrote sbom %d bytes to %s with packages:%d, files:%d, deps:%d, snips:%d otherLics:%d, annotations:%d, externaldocRefs:%d",
		len(buf), outName,
		len(m.out.Packages), len(m.out.Files), len(m.out.Relationships),
		len(m.out.Snippets), len(m.out.OtherLicenses), len(m.out.Annotations),
		len(m.out.ExternalDocumentReferences))

	return nil
}
