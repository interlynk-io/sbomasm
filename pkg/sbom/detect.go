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

package sbom

import (
	"bufio"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"strings"

	"gopkg.in/yaml.v2"
)

type SBOMSpec string

const (
	SBOMSpecSPDX    SBOMSpec = "spdx"
	SBOMSpecCDX     SBOMSpec = "cdx"
	SBOMSpecUnknown SBOMSpec = "unknown"
)

type FileFormat string

const (
	FileFormatJSON     FileFormat = "json"
	FileFormatRDF      FileFormat = "rdf"
	FileFormatYAML     FileFormat = "yaml"
	FileFormatTagValue FileFormat = "tag-value"
	FileFormatXML      FileFormat = "xml"
	FileFormatUnknown  FileFormat = "unknown"
)

type spdxbasic struct {
	ID string `json:"SPDXID" yaml:"SPDXID"`
}

type cdxbasic struct {
	XMLNS     string `json:"-" xml:"xmlns,attr"`
	BOMFormat string `json:"bomFormat" xml:"-"`
}

func Detect(f io.ReadSeeker) (SBOMSpec, FileFormat, error) {
	defer f.Seek(0, io.SeekStart)

	f.Seek(0, io.SeekStart)

	var s spdxbasic
	if err := json.NewDecoder(f).Decode(&s); err == nil {
		if strings.HasPrefix(s.ID, "SPDX") {
			return SBOMSpecSPDX, FileFormatJSON, nil
		}
	}

	f.Seek(0, io.SeekStart)

	var cdx cdxbasic
	if err := json.NewDecoder(f).Decode(&cdx); err == nil {
		if cdx.BOMFormat == "CycloneDX" {
			return SBOMSpecCDX, FileFormatJSON, nil
		}
	}

	f.Seek(0, io.SeekStart)

	// Use streaming XML parser to check only the root element's namespace
	// This allows detection even if the XML is malformed deeper in the document
	decoder := xml.NewDecoder(f)
	for {
		token, err := decoder.Token()
		if err != nil {
			break
		}
		if se, ok := token.(xml.StartElement); ok {
			// Check if this is the root element with CycloneDX namespace
			if se.Name.Space == "http://cyclonedx.org/schema/bom/1.6" ||
				se.Name.Space == "http://cyclonedx.org/schema/bom/1.5" ||
				se.Name.Space == "http://cyclonedx.org/schema/bom/1.4" ||
				se.Name.Space == "http://cyclonedx.org/schema/bom/1.3" ||
				se.Name.Space == "http://cyclonedx.org/schema/bom/1.2" ||
				se.Name.Space == "http://cyclonedx.org/schema/bom/1.1" ||
				se.Name.Space == "http://cyclonedx.org/schema/bom/1.0" ||
				strings.HasPrefix(se.Name.Space, "http://cyclonedx.org") {
				f.Seek(0, io.SeekStart)
				return SBOMSpecCDX, FileFormatXML, nil
			}
			// Not a CycloneDX document, stop checking
			break
		}
	}
	f.Seek(0, io.SeekStart)

	if sc := bufio.NewScanner(f); sc.Scan() {
		if strings.HasPrefix(sc.Text(), "SPDX") {
			return SBOMSpecSPDX, FileFormatTagValue, nil
		}
	}

	f.Seek(0, io.SeekStart)

	var y spdxbasic
	if err := yaml.NewDecoder(f).Decode(&y); err == nil {
		if strings.HasPrefix(y.ID, "SPDX") {
			return SBOMSpecSPDX, FileFormatYAML, nil
		}
	}

	return SBOMSpecUnknown, FileFormatUnknown, fmt.Errorf("unknown spec or format")
}

func DetectSbom(path string) (SBOMSpec, FileFormat, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", "", err
	}
	defer f.Close()

	spec, format, err := Detect(f)
	if err != nil {
		return "", "", err
	}
	return spec, format, nil
}
