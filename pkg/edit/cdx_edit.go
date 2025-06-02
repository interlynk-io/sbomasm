package edit

import (
	"fmt"
	"strings"

	cydx "github.com/CycloneDX/cyclonedx-go"
	"github.com/interlynk-io/sbomasm/pkg/logger"
	"github.com/samber/lo"
)

type cdxEditDoc struct {
	bom  *cydx.BOM
	comp *cydx.Component
	c    *configParams
}

func NewCdxEditDoc(b *cydx.BOM, c *configParams) (*cdxEditDoc, error) {
	doc := &cdxEditDoc{}

	doc.bom = b
	doc.c = c

	if c.search.subject == "primary-component" {
		if b.Metadata.Component == nil {
			return nil, fmt.Errorf("primary component is missing")
		}
		doc.comp = b.Metadata.Component
	}

	if c.search.subject == "component-name-version" {
		doc.comp = cdxFindComponent(b, c)
		if doc.comp == nil {
			return nil, fmt.Errorf("component is missing")
		}
	}

	return doc, nil
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
	if d.c.shouldTimeStamp() {
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
	// default sbomasm tool for tools.tools
	sbomasmTool := cydx.Tool{
		Name:    SBOMASM,
		Version: SBOMASM_VERSION,
	}

	// default sbomasm tool for tools.components
	sbomasmComponent := cydx.Component{
		Type:    cydx.ComponentTypeApplication,
		Name:    SBOMASM,
		Version: SBOMASM_VERSION,
	}

	// initialize the tool to cover case when tool section is not present
	// in that we still need to add sbomasm as a tool
	d.initializeMetadataTools()

	// get all tools explicity specified by the user via flag `--tool`
	newTools := cdxConstructTools(d.bom, d.c)

	// detect whether sbomasm is explicity specified by the user via flag `--tool` or not
	// if present then replace default sbomasm tool by provided sbomasm tool with version
	explicitSbomasm := d.detectExplicitTool(newTools.Tools, SBOMASM, &sbomasmTool)
	explicitSbomasmComponent := d.detectExplicitComponent(newTools.Components, SBOMASM, &sbomasmComponent)

	if explicitSbomasm {
		d.bom.Metadata.Tools.Tools = removeTool(d.bom.Metadata.Tools.Tools, SBOMASM)
	}
	if explicitSbomasmComponent {
		d.bom.Metadata.Tools.Components = removeComponent(d.bom.Metadata.Tools.Components, SBOMASM)
	}

	if d.c.onMissing() {
		d.addMissingToolsOrComponents(newTools, sbomasmTool, sbomasmComponent)
		return nil
	}

	if d.c.onAppend() {
		d.appendToolsOrComponents(newTools, sbomasmTool, sbomasmComponent)
		return nil
	}

	// neither missing nor append case
	d.mergeToolsOrComponents(newTools, sbomasmTool, sbomasmComponent)

	return nil
}

func (d *cdxEditDoc) initializeMetadataTools() {
	if d.bom.SpecVersion > cydx.SpecVersion1_4 {
		if d.bom.Metadata.Tools == nil {
			d.bom.Metadata.Tools = &cydx.ToolsChoice{
				Components: new([]cydx.Component),
			}
		}
		if d.bom.Metadata.Tools.Components == nil {
			d.bom.Metadata.Tools.Components = new([]cydx.Component)
		}
	} else {
		if d.bom.Metadata.Tools == nil {
			d.bom.Metadata.Tools = &cydx.ToolsChoice{
				Tools: new([]cydx.Tool),
			}
		}
		if d.bom.Metadata.Tools.Tools == nil {
			d.bom.Metadata.Tools.Tools = new([]cydx.Tool)
		}
	}
}

func (d *cdxEditDoc) detectExplicitTool(tools *[]cydx.Tool, sbomasmName string, sbomasmTool *cydx.Tool) bool {
	if tools != nil {
		for _, tool := range *tools {
			if tool.Name == sbomasmName {
				*sbomasmTool = tool
				return true
			}
		}
	}
	return false
}

func (d *cdxEditDoc) detectExplicitComponent(components *[]cydx.Component, sbomasmName string, sbomasmComponent *cydx.Component) bool {
	if components != nil {
		for _, component := range *components {
			if component.Name == sbomasmName {
				*sbomasmComponent = component
				return true
			}
		}
	}
	return false
}

// handle missing case for tools.tools and tools.components case
func (d *cdxEditDoc) addMissingToolsOrComponents(newTools *cydx.ToolsChoice, sbomasmTool cydx.Tool, sbomasmComponent cydx.Component) {
	if d.bom.SpecVersion > cydx.SpecVersion1_4 {
		d.bom.Metadata.Tools.Components = cdxUniqueComponents(*d.bom.Metadata.Tools.Components, *newTools.Components)
		if !componentExists(d.bom.Metadata.Tools.Components, sbomasmComponent) {
			*d.bom.Metadata.Tools.Components = append(*d.bom.Metadata.Tools.Components, sbomasmComponent)
		}
	} else {
		d.bom.Metadata.Tools.Tools = cdxUniqueTools(*d.bom.Metadata.Tools.Tools, *newTools.Tools)
		if !toolExists(d.bom.Metadata.Tools.Tools, sbomasmTool) {
			*d.bom.Metadata.Tools.Tools = append(*d.bom.Metadata.Tools.Tools, sbomasmTool)
		}
	}
}

// handle append case for tools.tools and tools.components case
func (d *cdxEditDoc) appendToolsOrComponents(newTools *cydx.ToolsChoice, sbomasmTool cydx.Tool, sbomasmComponent cydx.Component) {
	if d.bom.SpecVersion > cydx.SpecVersion1_4 {
		d.bom.Metadata.Tools.Components = cdxUniqueComponents(*d.bom.Metadata.Tools.Components, *newTools.Components)
		if !componentExists(d.bom.Metadata.Tools.Components, sbomasmComponent) {
			*d.bom.Metadata.Tools.Components = append(*d.bom.Metadata.Tools.Components, sbomasmComponent)
		}
	} else {
		d.bom.Metadata.Tools.Tools = cdxUniqueTools(*d.bom.Metadata.Tools.Tools, *newTools.Tools)
		if !toolExists(d.bom.Metadata.Tools.Tools, sbomasmTool) {
			*d.bom.Metadata.Tools.Tools = append(*d.bom.Metadata.Tools.Tools, sbomasmTool)
		}
	}
}

// handle default case for tools.tools and tools.components case
func (d *cdxEditDoc) mergeToolsOrComponents(newTools *cydx.ToolsChoice, sbomasmTool cydx.Tool, sbomasmComponent cydx.Component) {
	if d.bom.SpecVersion > cydx.SpecVersion1_4 {
		d.bom.Metadata.Tools.Components = cdxUniqueComponents(*d.bom.Metadata.Tools.Components, *newTools.Components)
		if !componentExists(d.bom.Metadata.Tools.Components, sbomasmComponent) {
			*d.bom.Metadata.Tools.Components = append(*d.bom.Metadata.Tools.Components, sbomasmComponent)
		}
	} else {
		d.bom.Metadata.Tools.Tools = cdxUniqueTools(*d.bom.Metadata.Tools.Tools, *newTools.Tools)
		if !toolExists(d.bom.Metadata.Tools.Tools, sbomasmTool) {
			*d.bom.Metadata.Tools.Tools = append(*d.bom.Metadata.Tools.Tools, sbomasmTool)
		}
	}
}

func toolExists(tools *[]cydx.Tool, tool cydx.Tool) bool {
	if tools == nil {
		return false
	}
	for _, t := range *tools {
		if t.Name == tool.Name && t.Version == tool.Version {
			return true
		}
	}
	return false
}

// Check if a component exists
func componentExists(components *[]cydx.Component, component cydx.Component) bool {
	if components == nil {
		return false
	}
	for _, c := range *components {
		if c.Name == component.Name && c.Version == component.Version {
			return true
		}
	}
	return false
}

func cdxUniqueTools(existing, newTools []cydx.Tool) *[]cydx.Tool {
	toolSet := make(map[string]struct{})
	uniqueTools := []cydx.Tool{}

	for _, t := range existing {
		key := fmt.Sprintf("%s-%s", strings.ToLower(t.Name), strings.ToLower(t.Version))
		toolSet[key] = struct{}{}
		uniqueTools = append(uniqueTools, t)
	}

	for _, t := range newTools {
		key := fmt.Sprintf("%s-%s", strings.ToLower(t.Name), strings.ToLower(t.Version))
		if _, exists := toolSet[key]; !exists {
			uniqueTools = append(uniqueTools, t)
		}
	}

	return &uniqueTools
}

func cdxUniqueComponents(existing, newComponents []cydx.Component) *[]cydx.Component {
	componentSet := make(map[string]struct{})
	uniqueComponents := []cydx.Component{}

	for _, c := range existing {
		key := fmt.Sprintf("%s-%s", strings.ToLower(c.Name), strings.ToLower(c.Version))
		componentSet[key] = struct{}{}
		uniqueComponents = append(uniqueComponents, c)
	}

	for _, c := range newComponents {
		key := fmt.Sprintf("%s-%s", strings.ToLower(c.Name), strings.ToLower(c.Version))
		if _, exists := componentSet[key]; !exists {
			uniqueComponents = append(uniqueComponents, c)
		}
	}

	return &uniqueComponents
}

func removeTool(tools *[]cydx.Tool, name string) *[]cydx.Tool {
	if tools == nil {
		return nil
	}
	filtered := []cydx.Tool{}
	for _, t := range *tools {
		if t.Name != name {
			filtered = append(filtered, t)
		}
	}
	return &filtered
}

func removeComponent(components *[]cydx.Component, name string) *[]cydx.Component {
	if components == nil {
		return nil
	}
	filtered := []cydx.Component{}
	for _, c := range *components {
		if c.Name != name {
			filtered = append(filtered, c)
		}
	}
	return &filtered
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
