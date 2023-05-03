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

package detect

import (
	"bufio"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"strings"

	"gopkg.in/yaml.v2"
)

type SBOMSpecFormat string

const (
	SBOMSpecSPDX    SBOMSpecFormat = "spdx"
	SBOMSpecCDX     SBOMSpecFormat = "cyclonedx"
	SBOMSpecUnknown SBOMSpecFormat = "unknown"
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

func Detect(f io.ReadSeeker) (SBOMSpecFormat, FileFormat, error) {
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

	if err := xml.NewDecoder(f).Decode(&cdx); err == nil {
		if strings.HasPrefix(cdx.XMLNS, "http://cyclonedx.org") {
			return SBOMSpecCDX, FileFormatXML, nil
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

	return "", "", fmt.Errorf("unknown spec or format")
}
