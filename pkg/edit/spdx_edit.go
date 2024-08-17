package edit

import (
	"fmt"
	"strings"

	"github.com/interlynk-io/sbomasm/pkg/logger"
	"github.com/samber/lo"
	"github.com/spdx/tools-golang/spdx"
)

type spdxEditDoc struct {
	bom *spdx.Document
	pkg *spdx.Package
	c   *configParams
}

func NewSpdxEditDoc(bom *spdx.Document, c *configParams) *spdxEditDoc {
	doc := &spdxEditDoc{}

	doc.bom = bom
	doc.c = c

	if c.search.subject == "primary-component" {
		pkg, err := spdxFindPkg(bom, c, true)
		if err == nil {
			doc.pkg = pkg
		}
	}

	if c.search.subject == "component-name-version" {
		pkg, err := spdxFindPkg(bom, c, false)
		if err == nil {
			doc.pkg = pkg
		}
	}
	return doc
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

	if d.c.search.subject == "document" {
		return errNotSupported
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

	foundPurl := false
	for _, ref := range d.pkg.PackageExternalReferences {
		if ref.RefType == "purl" {
			foundPurl = true
		}
	}

	if d.c.onMissing() {
		if !foundPurl {
			if d.pkg.PackageExternalReferences == nil {
				d.pkg.PackageExternalReferences = []*spdx.PackageExternalReference{}
			}
			d.pkg.PackageExternalReferences = append(d.pkg.PackageExternalReferences, &purl)
		}
	} else if d.c.onAppend() {
		if !foundPurl {
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
				return strings.ToLower(x.RefType) == "cpe23Type"
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
	if !d.c.shouldTools() {
		return errNoConfiguration
	}

	if d.c.search.subject != "document" {
		return errNotSupported
	}

	tools := []spdx.Creator{}

	for _, tool := range d.c.tools {
		tools = append(tools, spdx.Creator{
			CreatorType: "Tool",
			Creator:     fmt.Sprintf("%s (%s)", tool.name, tool.value),
		})
	}

	if d.c.onMissing() {
		if d.bom.CreationInfo == nil {
			d.bom.CreationInfo = &spdx.CreationInfo{
				Creators: tools,
			}
		} else if d.bom.CreationInfo.Creators == nil {
			d.bom.CreationInfo.Creators = tools
		} else {
			d.bom.CreationInfo.Creators = append(d.bom.CreationInfo.Creators, tools...)
		}
	} else if d.c.onAppend() {
		if d.bom.CreationInfo == nil {
			d.bom.CreationInfo = &spdx.CreationInfo{
				Creators: tools,
			}
		} else if d.bom.CreationInfo.Creators == nil {
			d.bom.CreationInfo.Creators = tools
		} else {
			d.bom.CreationInfo.Creators = append(d.bom.CreationInfo.Creators, tools...)
		}
	} else {
		if d.bom.CreationInfo == nil {
			d.bom.CreationInfo = &spdx.CreationInfo{
				Creators: tools,
			}
		} else {
			d.bom.CreationInfo.Creators = tools
		}
	}
	return nil
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

	if d.c.search.subject == "document" {
		return errNotSupported
	}

	if d.c.onMissing() {
		if d.pkg.PackageDescription == "" {
			d.pkg.PackageDescription = d.c.description
		}
	} else {
		d.pkg.PackageDescription = d.c.description
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
	if !d.c.shouldTimeStamp() {
		return errNoConfiguration
	}

	if d.c.search.subject != "document" {
		return errNotSupported
	}

	if d.c.onMissing() {
		if d.bom.CreationInfo == nil {
			d.bom.CreationInfo = &spdx.CreationInfo{}
		}

		if d.bom.CreationInfo.Created == "" {
			d.bom.CreationInfo.Created = utcNowTime()
		}
	} else {
		if d.bom.CreationInfo == nil {
			d.bom.CreationInfo = &spdx.CreationInfo{}
		}

		d.bom.CreationInfo.Created = utcNowTime()
	}
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
