package edit

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	cydx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/uuid"

	"github.com/interlynk-io/sbomasm/pkg/detect"
	liclib "github.com/interlynk-io/sbomasm/pkg/licenses"
	"github.com/interlynk-io/sbomasm/pkg/logger"
)

var cdx_strings_to_types = map[string]cydx.ComponentType{
	"application":      cydx.ComponentTypeApplication,
	"container":        cydx.ComponentTypeContainer,
	"device":           cydx.ComponentTypeDevice,
	"file":             cydx.ComponentTypeFile,
	"framework":        cydx.ComponentTypeFramework,
	"library":          cydx.ComponentTypeLibrary,
	"firmware":         cydx.ComponentTypeFirmware,
	"operating-system": cydx.ComponentTypeOS,
}

var cdx_hash_algos = map[string]cydx.HashAlgorithm{
	"MD5":         cydx.HashAlgoMD5,
	"SHA-1":       cydx.HashAlgoSHA1,
	"SHA-256":     cydx.HashAlgoSHA256,
	"SHA-384":     cydx.HashAlgoSHA384,
	"SHA-512":     cydx.HashAlgoSHA512,
	"SHA3-256":    cydx.HashAlgoSHA3_256,
	"SHA3-384":    cydx.HashAlgoSHA3_384,
	"SHA3-512":    cydx.HashAlgoSHA3_512,
	"BLAKE2b-256": cydx.HashAlgoBlake2b_256,
	"BLAKE2b-384": cydx.HashAlgoBlake2b_384,
	"BLAKE2b-512": cydx.HashAlgoBlake2b_512,
	"BLAKE3":      cydx.HashAlgoBlake3,
}

var cdx_lifecycle_phases = map[string]cydx.LifecyclePhase{
	"design":       cydx.LifecyclePhaseDesign,
	"pre-build":    cydx.LifecyclePhasePreBuild,
	"build":        cydx.LifecyclePhaseBuild,
	"post-build":   cydx.LifecyclePhasePostBuild,
	"operations":   cydx.LifecyclePhaseOperations,
	"discovery":    cydx.LifecyclePhaseDiscovery,
	"decommission": cydx.LifecyclePhaseDecommission,
}

func cdxEdit(c *configParams) error {
	log := logger.FromContext(*c.ctx)

	bom, err := loadCdxBom(*c.ctx, c.inputFilePath)
	if err != nil {
		return err
	}

	doc, err := NewCdxEditDoc(bom, c)
	if doc == nil {
		return fmt.Errorf("failed to edit cdx document: %w", err)
	}

	if c.shouldSearch() && doc.comp == nil {
		return errors.New(fmt.Sprintf("component not found: %s, %s", c.search.name, c.search.version))
	}

	if doc.comp != nil {
		log.Debugf("Component found %s, %s", doc.comp.Name, doc.comp.Version)
	}

	doc.update()

	return writeCdxBom(doc.bom, c)
}

func loadCdxBom(ctx context.Context, path string) (*cydx.BOM, error) {
	log := logger.FromContext(ctx)

	var err error
	var bom *cydx.BOM

	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	spec, format, err := detect.Detect(f)
	if err != nil {
		return nil, err
	}

	log.Debugf("loading bom:%s spec:%s format:%s", path, spec, format)

	switch format {
	case detect.FileFormatJSON:
		bom = new(cydx.BOM)
		decoder := cydx.NewBOMDecoder(f, cydx.BOMFileFormatJSON)
		if err = decoder.Decode(bom); err != nil {
			return nil, err
		}
	case detect.FileFormatXML:
		bom = new(cydx.BOM)
		decoder := cydx.NewBOMDecoder(f, cydx.BOMFileFormatXML)
		if err = decoder.Decode(bom); err != nil {
			return nil, err
		}
	default:
		panic("unsupported file format") // TODO: return error instead of panic
	}

	return bom, nil
}

func writeCdxBom(bom *cydx.BOM, c *configParams) error {
	var f io.Writer

	// Always generate a new serial number on edit
	bom.SerialNumber = newCdxSerialNumber()

	if c.outputFilePath == "" {
		f = os.Stdout
	} else {
		var err error
		f, err = os.Create(c.outputFilePath)
		if err != nil {
			return err
		}
	}

	inf, err := os.Open(c.inputFilePath)
	if err != nil {
		return err
	}
	defer inf.Close()

	_, format, err := detect.Detect(inf)
	if err != nil {
		return err
	}

	var encoder cydx.BOMEncoder

	switch format {
	case detect.FileFormatJSON:
		encoder = cydx.NewBOMEncoder(f, cydx.BOMFileFormatJSON)
	case detect.FileFormatXML:
		encoder = cydx.NewBOMEncoder(f, cydx.BOMFileFormatXML)
	}

	encoder.SetPretty(true)
	encoder.SetEscapeHTML(true)

	if err := encoder.Encode(bom); err != nil {
		return err
	}

	return nil
}

func cdxFindComponent(b *cydx.BOM, c *configParams) *cydx.Component {
	if c.search.subject != "component-name-version" {
		return nil
	}

	for i := range *b.Components {
		comp := &(*b.Components)[i]
		if comp.Name == c.search.name && comp.Version == c.search.version {
			return comp
		}
	}

	return nil
}

func cdxUniqTools(a *cydx.ToolsChoice, b *cydx.ToolsChoice) *cydx.ToolsChoice {
	choices := cydx.ToolsChoice{}

	if a == nil && b == nil {
		return &choices
	}

	if a == nil && b != nil {
		return b
	}

	if a != nil && b == nil {
		return a
	}

	if a.Tools != nil && b.Tools != nil {
		choices.Tools = new([]cydx.Tool)
		uniqTools := make(map[string]string)

		for _, tool := range *a.Tools {
			key := fmt.Sprintf("%s-%s", strings.ToLower(tool.Name), strings.ToLower(tool.Version))

			if _, ok := uniqTools[key]; !ok {
				*choices.Tools = append(*choices.Tools, tool)
				uniqTools[key] = key
			}
		}

		for _, tool := range *b.Tools {
			key := fmt.Sprintf("%s-%s", strings.ToLower(tool.Name), strings.ToLower(tool.Version))

			if _, ok := uniqTools[key]; !ok {
				*choices.Tools = append(*choices.Tools, tool)
				uniqTools[key] = key
			}
		}
	}

	if a.Components != nil && b.Components != nil {
		choices.Components = new([]cydx.Component)
		uniqTools := make(map[string]string)

		for _, tool := range *a.Components {
			key := fmt.Sprintf("%s-%s", strings.ToLower(tool.Name), strings.ToLower(tool.Version))

			if _, ok := uniqTools[key]; !ok {
				*choices.Components = append(*choices.Components, tool)
				uniqTools[key] = key
			}
		}

		for _, tool := range *b.Components {
			key := fmt.Sprintf("%s-%s", strings.ToLower(tool.Name), strings.ToLower(tool.Version))

			if _, ok := uniqTools[key]; !ok {
				*choices.Components = append(*choices.Components, tool)
				uniqTools[key] = key
			}
		}
	}

	if a.Services != nil && b.Services != nil {
		choices.Services = new([]cydx.Service)
		uniqTools := make(map[string]string)

		for _, tool := range *a.Services {
			key := fmt.Sprintf("%s-%s", strings.ToLower(tool.Name), strings.ToLower(tool.Version))

			if _, ok := uniqTools[key]; !ok {
				*choices.Services = append(*choices.Services, tool)
				uniqTools[key] = key
			}
		}

		for _, tool := range *b.Services {
			key := fmt.Sprintf("%s-%s", strings.ToLower(tool.Name), strings.ToLower(tool.Version))

			if _, ok := uniqTools[key]; !ok {
				*choices.Services = append(*choices.Services, tool)
				uniqTools[key] = key
			}
		}
	}

	return &choices
}

func cdxConstructTools(b *cydx.BOM, c *configParams) *cydx.ToolsChoice {
	choice := cydx.ToolsChoice{}

	if b.SpecVersion > cydx.SpecVersion1_4 {
		choice.Components = new([]cydx.Component)
	} else {
		choice.Tools = new([]cydx.Tool)
	}

	uniqTools := make(map[string]string)

	for _, tool := range c.tools {
		key := fmt.Sprintf("%s-%s", strings.ToLower(tool.name), strings.ToLower(tool.value))

		if _, ok := uniqTools[key]; !ok {
			if b.SpecVersion > cydx.SpecVersion1_4 {
				*choice.Components = append(*choice.Components, cydx.Component{
					Type:    cydx.ComponentTypeApplication,
					Name:    tool.name,
					Version: tool.value,
				})
			} else {
				*choice.Tools = append(*choice.Tools, cydx.Tool{
					Name:    tool.name,
					Version: tool.value,
				})
			}

			uniqTools[key] = key
		}
	}

	return &choice
}

func cdxConstructHashes(_ *cydx.BOM, c *configParams) *[]cydx.Hash {
	hashes := []cydx.Hash{}

	for _, hash := range c.hashes {
		hashes = append(hashes, cydx.Hash{
			Algorithm: cydx.HashAlgorithm(hash.name),
			Value:     hash.value,
		})
	}

	return &hashes
}

func cdxConstructLicenses(_ *cydx.BOM, c *configParams) cydx.Licenses {
	licenses := cydx.Licenses{}

	for _, license := range c.licenses {
		if liclib.IsSpdxExpression(license.name) {
			licenses = append(licenses, cydx.LicenseChoice{
				Expression: license.name,
			})
		} else {
			lic, err := liclib.LookupSpdxLicense(license.name)
			if err != nil {
				licenses = append(licenses, cydx.LicenseChoice{
					License: &cydx.License{
						BOMRef: newBomRef(),
						Name:   license.name,
						URL:    license.value,
					},
				})
			} else {
				licenses = append(licenses, cydx.LicenseChoice{
					License: &cydx.License{
						BOMRef: newBomRef(),
						ID:     lic.ShortID(),
						Name:   lic.Name(),
						URL:    license.value,
					},
				})
			}
		}
	}
	return licenses
}

func cdxConstructSupplier(_ *cydx.BOM, c *configParams) *cydx.OrganizationalEntity {
	entity := cydx.OrganizationalEntity{
		BOMRef: newBomRef(),
		Name:   c.supplier.name,
		URL: &[]string{
			c.supplier.value,
		},
	}
	return &entity
}

func cdxConstructAuthors(_ *cydx.BOM, c *configParams) *[]cydx.OrganizationalContact {
	authors := []cydx.OrganizationalContact{}

	for _, author := range c.authors {
		authors = append(authors, cydx.OrganizationalContact{
			BOMRef: newBomRef(),
			Name:   author.name,
			Email:  author.value,
		})
	}

	return &authors
}

func newCdxSerialNumber() string {
	u := uuid.New().String()

	return fmt.Sprintf("urn:uuid:%s", u)
}

func newBomRef() string {
	u := uuid.New().String()

	return fmt.Sprintf("sbomasm:%s", u)
}
