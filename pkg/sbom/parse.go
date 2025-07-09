package sbom

import (
	"fmt"
	"io"
	"os"

	cydx "github.com/CycloneDX/cyclonedx-go"
	spdx_json "github.com/spdx/tools-golang/json"
	spdx_rdf "github.com/spdx/tools-golang/rdf"
	"github.com/spdx/tools-golang/spdx/common"
	spdx_tv "github.com/spdx/tools-golang/tagvalue"
	spdx_yaml "github.com/spdx/tools-golang/yaml"
)

func ParseSBOM(f *os.File, spec SBOMSpecFormat, format FileFormat) (SBOMDocument, error) {
	if f == nil {
		return nil, fmt.Errorf("no SBOM file provided")
	}
	f.Seek(0, io.SeekStart)

	switch spec {
	case SBOMSpecSPDX:
		return ParseSPDXSBOM(f, format)
	case SBOMSpecCDX:
		return ParseCDXSBOM(f, format)
	default:
		return nil, fmt.Errorf("unsupported sbom spec: %s", spec)

	}
}

func ParseSPDXSBOM(f *os.File, format FileFormat) (SBOMDocument, error) {
	var d common.AnyDocument
	var err error

	switch format {
	case FileFormatJSON:
		d, err = spdx_json.Read(f)
	case FileFormatTagValue:
		d, err = spdx_tv.Read(f)
	case FileFormatYAML:
		d, err = spdx_yaml.Read(f)
	case FileFormatRDF:
		d, err = spdx_rdf.Read(f)
	default:
		return nil, fmt.Errorf("unsupported SPDX format: %s", format)

	}
	return &SPDXDocument{Doc: d}, err
}

func ParseCDXSBOM(f *os.File, format FileFormat) (SBOMDocument, error) {
	var err error
	var bom *cydx.BOM

	switch format {
	case FileFormatJSON:
		bom = new(cydx.BOM)
		decoder := cydx.NewBOMDecoder(f, cydx.BOMFileFormatJSON)
		if err = decoder.Decode(bom); err != nil {
			return nil, err
		}
	case FileFormatXML:
		bom = new(cydx.BOM)
		decoder := cydx.NewBOMDecoder(f, cydx.BOMFileFormatXML)
		if err = decoder.Decode(bom); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported CDX format: %s", format)
	}

	return &CycloneDXDocument{BOM: bom}, nil
}
