// Copyright 2025 Interlynk.io
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
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

// FormatVersion represents the version string of an SBOM specification
type FormatVersion string

type spdxbasic struct {
	ID      string `json:"SPDXID" yaml:"SPDXID"`
	Version string `json:"spdxVersion" yaml:"spdxVersion"`
}

// spdx3Basic is used to detect SPDX 3.0 JSON-LD format
type spdx3Basic struct {
	Context interface{} `json:"@context"` // Can be string or array
}

type cdxbasic struct {
	XMLNS     string `json:"-" xml:"xmlns,attr"`
	BOMFormat string `json:"bomFormat" xml:"-"`
}

func Detect(f io.ReadSeeker) (SBOMSpec, FileFormat, FormatVersion, error) {
	defer f.Seek(0, io.SeekStart)

	f.Seek(0, io.SeekStart)

	// Check for SPDX 3.0 first (JSON-LD format with @context)
	var s3 spdx3Basic
	if err := json.NewDecoder(f).Decode(&s3); err == nil {
		contextStr := extractContextString(s3.Context)
		if strings.Contains(contextStr, "spdx.org/rdf/3.0") {
			version := ""
			if strings.Contains(contextStr, "3.0.1") {
				version = "SPDX-3.0.1"
			} else if strings.Contains(contextStr, "/3.0/") || strings.HasSuffix(contextStr, "/3.0") {
				version = "SPDX-3.0"
			}
			if version != "" {
				return SBOMSpecSPDX, FileFormatJSON, FormatVersion(version), nil
			}
		}
	}

	f.Seek(0, io.SeekStart)

	var s spdxbasic
	if err := json.NewDecoder(f).Decode(&s); err == nil {
		if strings.HasPrefix(s.ID, "SPDX") {
			return SBOMSpecSPDX, FileFormatJSON, FormatVersion(s.Version), nil
		}
	}

	f.Seek(0, io.SeekStart)

	var cdx cdxbasic
	if err := json.NewDecoder(f).Decode(&cdx); err == nil {
		if cdx.BOMFormat == "CycloneDX" {
			return SBOMSpecCDX, FileFormatJSON, "", nil
		}
	}

	f.Seek(0, io.SeekStart)

	if err := xml.NewDecoder(f).Decode(&cdx); err == nil {
		if strings.HasPrefix(cdx.XMLNS, "http://cyclonedx.org") {
			return SBOMSpecCDX, FileFormatXML, "", nil
		}
	}
	f.Seek(0, io.SeekStart)

	if sc := bufio.NewScanner(f); sc.Scan() {
		if strings.HasPrefix(sc.Text(), "SPDX") {
			return SBOMSpecSPDX, FileFormatTagValue, "", nil
		}
	}

	f.Seek(0, io.SeekStart)

	var y spdxbasic
	if err := yaml.NewDecoder(f).Decode(&y); err == nil {
		if strings.HasPrefix(y.ID, "SPDX") {
			return SBOMSpecSPDX, FileFormatYAML, FormatVersion(y.Version), nil
		}
	}

	return SBOMSpecUnknown, FileFormatUnknown, "", fmt.Errorf("unknown spec or format")
}

// isSpdx3Version checks if the version string indicates a supported SPDX 3.x version
func isSpdx3Version(version string) bool {
	// Handle formats like "SPDX-3.0", "SPDX-3.0.1", "3.0", "3.0.1"
	v := strings.ToLower(version)
	v = strings.TrimPrefix(v, "spdx-")

	// Only support SPDX 3.0.x versions (3.0, 3.0.1, etc.)
	return strings.HasPrefix(v, "3.0")
}

// extractContextString extracts the SPDX context string from SPDX 3.0 JSON-LD
func extractContextString(context interface{}) string {
	if context == nil {
		return ""
	}

	switch v := context.(type) {
	case string:
		return v
	case []interface{}:
		// Scan all contexts and return the first SPDX context
		for _, item := range v {
			if s, ok := item.(string); ok && strings.Contains(s, "spdx.org/rdf/3.0") {
				return s
			}
		}
	}
	return ""
}

func DetectSbom(path string) (SBOMSpec, FileFormat, FormatVersion, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", "", "", err
	}
	defer f.Close()

	spec, format, version, err := Detect(f)
	if err != nil {
		return "", "", "", err
	}
	return spec, format, version, nil
}
