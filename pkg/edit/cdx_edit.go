package edit

import (
	"fmt"

	cydx "github.com/CycloneDX/cyclonedx-go"
	"github.com/interlynk-io/sbomasm/pkg/logger"
	"github.com/samber/lo"
)

type cdxEditDoc struct {
	bom  *cydx.BOM
	comp *cydx.Component
	c    *configParams
}

func NewCdxEditDoc(b *cydx.BOM, c *configParams) *cdxEditDoc {
	doc := &cdxEditDoc{}

	doc.bom = b
	doc.c = c

	if c.search.subject == "primary-component" {
		doc.comp = b.Metadata.Component
	}

	if c.search.subject == "component-name-version" {
		doc.comp = cdxFindComponent(b, c)
	}

	return doc
}

func (d *cdxEditDoc) update() {
	log := logger.FromContext(*d.c.ctx)
	log.Debug("CDX updating sbom")

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
				log.Infof(fmt.Sprintf("CDX error updating %s: %s", item.name, err))
			}
		}
	}

}

func (d *cdxEditDoc) timeStamp() error {
	if !d.c.shouldTimeStamp() {
		return errNoConfiguration
	}

	if d.c.search.subject != "document" {
		return errNotSupported
	}

	if d.c.onMissing() {
		if d.bom.Metadata.Timestamp == "" {
			d.bom.Metadata.Timestamp = utcNowTime()
		}
	} else {
		d.bom.Metadata.Timestamp = utcNowTime()
	}

	return nil
}

func (d *cdxEditDoc) lifeCycles() error {
	if !d.c.shouldLifeCycle() {
		return errNoConfiguration
	}

	if d.c.search.subject != "document" {
		return errNotSupported
	}

	lc := []cydx.Lifecycle{}

	for _, phase := range d.c.lifecycles {
		lc = append(lc, cydx.Lifecycle{
			Phase: cydx.LifecyclePhase(phase),
		})
	}

	if d.c.onMissing() {
		if d.bom.Metadata.Lifecycles == nil {
			d.bom.Metadata.Lifecycles = &lc
		}
	} else if d.c.onAppend() {
		if d.bom.Metadata.Lifecycles == nil {
			d.bom.Metadata.Lifecycles = &lc
		} else {
			*d.bom.Metadata.Lifecycles = append(*d.bom.Metadata.Lifecycles, lc...)
		}
	} else {
		d.bom.Metadata.Lifecycles = &lc
	}

	return nil
}

func (d *cdxEditDoc) typ() error {
	if !d.c.shouldTyp() {
		return errNoConfiguration
	}

	if d.c.search.subject == "document" {
		return errNotSupported
	}

	if d.c.onMissing() {
		if d.comp.Type == "" {
			d.comp.Type = cydx.ComponentType(d.c.typ)
		}
	} else {
		d.comp.Type = cydx.ComponentType(d.c.typ)
	}

	return nil
}

func (d *cdxEditDoc) repository() error {
	if !d.c.shouldRepository() {
		return errNoConfiguration
	}

	vcs := cydx.ExternalReference{
		Type: cydx.ERTypeVCS,
		URL:  d.c.repository,
	}

	var foundVcs *cydx.ExternalReference

	if d.c.search.subject != "document" {
		if d.comp.ExternalReferences != nil {
			for _, ref := range *d.comp.ExternalReferences {
				if ref.Type == cydx.ERTypeVCS {
					foundVcs = &ref
					break
				}
			}
		}
	} else {
		if d.bom.ExternalReferences != nil {
			for _, ref := range *d.bom.ExternalReferences {
				if ref.Type == cydx.ERTypeVCS {
					foundVcs = &ref
					break
				}
			}
		}
	}

	if d.c.onMissing() {
		if foundVcs == nil {
			if d.c.search.subject != "document" {
				if d.comp.ExternalReferences == nil {
					d.comp.ExternalReferences = &[]cydx.ExternalReference{}
				}
				*d.comp.ExternalReferences = append(*d.comp.ExternalReferences, vcs)
			} else {
				if d.bom.ExternalReferences == nil {
					d.bom.ExternalReferences = &[]cydx.ExternalReference{}
				}
				*d.bom.ExternalReferences = append(*d.bom.ExternalReferences, vcs)
			}
		}
	} else if d.c.onAppend() {
		if d.c.search.subject != "document" {
			if d.comp.ExternalReferences == nil {
				d.comp.ExternalReferences = &[]cydx.ExternalReference{}
			}
			*d.comp.ExternalReferences = append(*d.comp.ExternalReferences, vcs)
		} else {
			if d.bom.ExternalReferences == nil {
				d.bom.ExternalReferences = &[]cydx.ExternalReference{}
			}
			*d.bom.ExternalReferences = append(*d.bom.ExternalReferences, vcs)
		}
	} else {
		if foundVcs != nil {
			if d.c.search.subject != "document" {
				extRef := lo.Reject(*d.comp.ExternalReferences, func(x cydx.ExternalReference, _ int) bool {
					return x.Type == vcs.Type && x.URL == vcs.URL
				})
				*d.comp.ExternalReferences = extRef
			} else {
				extRef := lo.Reject(*d.bom.ExternalReferences, func(x cydx.ExternalReference, _ int) bool {
					return x.Type == vcs.Type && x.URL == vcs.URL
				})
				*d.bom.ExternalReferences = extRef
			}
		}

		if d.c.search.subject != "document" {
			if d.comp.ExternalReferences == nil {
				d.comp.ExternalReferences = &[]cydx.ExternalReference{}
			}
			*d.comp.ExternalReferences = append(*d.comp.ExternalReferences, vcs)
		} else {
			if d.bom.ExternalReferences == nil {
				d.bom.ExternalReferences = &[]cydx.ExternalReference{}
			}
			*d.bom.ExternalReferences = append(*d.bom.ExternalReferences, vcs)
		}
	}
	return nil
}

func (d *cdxEditDoc) description() error {
	if !d.c.shouldDescription() {
		return errNoConfiguration
	}

	if d.c.search.subject == "document" {
		return errNotSupported
	}

	if d.c.onMissing() {
		if d.comp.Description == "" {
			d.comp.Description = d.c.description
		}
	} else {
		d.comp.Description = d.c.description
	}

	return nil
}

func (d *cdxEditDoc) copyright() error {
	if !d.c.shouldCopyRight() {
		return errNoConfiguration
	}

	if d.c.search.subject == "document" {
		return errNotSupported
	}

	if d.c.onMissing() {
		if d.comp.Copyright == "" {
			d.comp.Copyright = d.c.copyright
		}
	} else {
		d.comp.Copyright = d.c.copyright
	}

	return nil
}

func (d *cdxEditDoc) tools() error {
	if !d.c.shouldTools() {
		return errNoConfiguration
	}

	if d.c.search.subject != "document" {
		return errNotSupported
	}

	choice := cdxConstructTools(d.bom, d.c)

	if d.c.onMissing() {
		if d.bom.Metadata.Tools == nil {
			d.bom.Metadata.Tools = choice
		}
	} else if d.c.onAppend() {
		if d.bom.Metadata.Tools != nil {
			if d.bom.SpecVersion > cydx.SpecVersion1_4 {
				if d.bom.Metadata.Tools.Components == nil {
					d.bom.Metadata.Tools.Components = &[]cydx.Component{}
				}

				*d.bom.Metadata.Tools.Components = append(*d.bom.Metadata.Tools.Components, *choice.Components...)
			} else {
				if d.bom.Metadata.Tools.Tools == nil {
					d.bom.Metadata.Tools.Tools = &[]cydx.Tool{}
				}
				*d.bom.Metadata.Tools.Tools = append(*d.bom.Metadata.Tools.Tools, *choice.Tools...)
			}
		} else {
			d.bom.Metadata.Tools = choice
		}
	} else {
		d.bom.Metadata.Tools = choice
	}

	return nil
}

func (d *cdxEditDoc) hashes() error {
	if !d.c.shouldHashes() {
		return errNoConfiguration
	}

	if d.c.search.subject == "document" {
		return errNotSupported
	}

	h := cdxConstructHashes(d.bom, d.c)

	if d.c.onMissing() {
		if d.comp.Hashes == nil {
			d.comp.Hashes = h
		}
	} else if d.c.onAppend() {
		if d.comp.Hashes != nil {
			*d.comp.Hashes = append(*d.comp.Hashes, *h...)
		} else {
			d.comp.Hashes = h
		}
	} else {
		d.comp.Hashes = h
	}

	return nil
}

func (d *cdxEditDoc) licenses() error {
	if !d.c.shouldLicenses() {
		return errNoConfiguration
	}

	lics := cdxConstructLicenses(d.bom, d.c)

	if d.c.onMissing() {
		if d.c.search.subject == "document" {
			if d.bom.Metadata.Licenses == nil {
				d.bom.Metadata.Licenses = &lics
			}
		} else {
			d.comp.Licenses = &lics
		}
	} else if d.c.onAppend() {
		if d.c.search.subject == "document" {
			if d.bom.Metadata.Licenses != nil {
				*d.bom.Metadata.Licenses = append(*d.bom.Metadata.Licenses, lics...)
			} else {
				d.bom.Metadata.Licenses = &lics
			}
		} else {
			if d.comp.Licenses != nil {
				*d.comp.Licenses = append(*d.comp.Licenses, lics...)
			} else {
				d.comp.Licenses = &lics
			}
		}
	} else {
		if d.c.search.subject == "document" {
			d.bom.Metadata.Licenses = &lics
		} else {
			d.comp.Licenses = &lics
		}
	}
	return nil
}

func (d *cdxEditDoc) purl() error {
	if !d.c.shouldPurl() {
		return errNoConfiguration
	}

	if d.c.search.subject == "document" {
		return errNotSupported
	}

	if d.c.onMissing() {
		if d.comp.PackageURL == "" {
			d.comp.PackageURL = d.c.purl
		}
	} else {
		d.comp.PackageURL = d.c.purl
	}

	return nil
}

func (d *cdxEditDoc) cpe() error {
	if !d.c.shouldCpe() {
		return errNoConfiguration
	}

	if d.c.search.subject == "document" {
		return errNotSupported
	}

	if d.c.onMissing() {
		if d.comp.CPE == "" {
			d.comp.CPE = d.c.cpe
		}
	} else {
		d.comp.CPE = d.c.cpe
	}
	return nil
}

func (d *cdxEditDoc) name() error {
	if !d.c.shouldName() {
		return errNoConfiguration
	}

	if d.c.search.subject == "document" {
		return errNotSupported
	}

	if d.c.onMissing() {
		if d.comp.Name == "" {
			d.comp.Name = d.c.name
		}
	} else {
		d.comp.Name = d.c.name
	}
	return nil
}

func (d *cdxEditDoc) version() error {
	if !d.c.shouldVersion() {
		return errNoConfiguration
	}

	if d.c.search.subject == "document" {
		return errNotSupported
	}

	if d.c.onMissing() {
		if d.comp.Version == "" {
			d.comp.Version = d.c.version
		}
	} else {
		d.comp.Version = d.c.version
	}
	return nil
}

func (d *cdxEditDoc) supplier() error {
	if !d.c.shouldSupplier() {
		return errNoConfiguration
	}

	supplier := cdxConstructSupplier(d.bom, d.c)

	if d.c.onMissing() {
		if d.c.search.subject == "document" {
			if d.bom.Metadata.Supplier == nil {
				d.bom.Metadata.Supplier = supplier
			}
		} else {
			if d.comp.Supplier == nil {
				d.comp.Supplier = supplier
			}
		}
	} else {
		if d.c.search.subject == "document" {
			d.bom.Metadata.Supplier = supplier
		} else {
			d.comp.Supplier = supplier
		}
	}

	return nil
}

func (d *cdxEditDoc) authors() error {
	if !d.c.shouldAuthors() {
		return errNoConfiguration
	}

	authors := cdxConstructAuthors(d.bom, d.c)

	if d.c.onMissing() {
		if d.c.search.subject == "document" {
			if d.bom.Metadata.Authors == nil {
				d.bom.Metadata.Authors = authors
			}
		} else {
			if d.bom.SpecVersion <= cydx.SpecVersion1_5 {
				if d.comp.Author == "" {
					d.comp.Author = d.c.getFormattedAuthors()
				}
			} else {
				if d.comp.Authors == nil {
					d.comp.Authors = authors
				}
			}
		}
	} else if d.c.onAppend() {
		if d.c.search.subject == "document" {
			*d.bom.Metadata.Authors = append(*d.bom.Metadata.Authors, *authors...)
		} else {
			if d.bom.SpecVersion <= cydx.SpecVersion1_5 {
				d.comp.Author = d.c.getFormattedAuthors()
				d.comp.Author = fmt.Sprintf("%s, %s", d.comp.Author, d.c.getFormattedAuthors())
			} else {
				*d.comp.Authors = append(*d.comp.Authors, *authors...)
			}
		}
	} else {
		if d.c.search.subject == "document" {
			d.bom.Metadata.Authors = authors
		} else {
			if d.bom.SpecVersion <= cydx.SpecVersion1_5 {
				d.comp.Author = d.c.getFormattedAuthors()
			} else {
				d.comp.Authors = authors
			}
		}
	}
	return nil
}
