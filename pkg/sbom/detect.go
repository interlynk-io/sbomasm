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

// SBOMSpec identifies the SBOM specification family.
type SBOMSpec string

const (
	SBOMSpecSPDX    SBOMSpec = "spdx"
	SBOMSpecCDX     SBOMSpec = "cdx"
	SBOMSpecUnknown SBOMSpec = "unknown"
)

// SPDX version constants for detection and parsing
const (
	spdxVersion30     = "3.0"
	spdxVersion301    = "3.0.1"
	spdxVersionPrefix = "SPDX-"
	spdxContextURL    = "spdx.org/rdf/3.0"
	spdxVersion20     = "SPDX-2.3"
	spdxVersion22     = "SPDX-2.2"
)

// Spdx3Version enumerates the supported SPDX 3.x versions.
type Spdx3Version string

const (
	SpdxVersion30  Spdx3Version = spdxVersion30
	SpdxVersion301 Spdx3Version = spdxVersion301
)

// FileFormat identifies the serialization format of an SBOM file.
type FileFormat string

const (
	FileFormatJSON     FileFormat = "json"
	FileFormatRDF      FileFormat = "rdf"
	FileFormatYAML     FileFormat = "yaml"
	FileFormatTagValue FileFormat = "tag-value"
	FileFormatXML      FileFormat = "xml"
	FileFormatUnknown  FileFormat = "unknown"
)

// FormatVersion represents the version string of an SBOM specification (e.g.
// "SPDX-2.3", "SPDX-3.0.1").
type FormatVersion string

// spdxbasic is a minimal struct for detecting SPDX 2.x JSON and YAML files.
type spdxbasic struct {
	ID      string `json:"SPDXID" yaml:"SPDXID"`
	Version string `json:"spdxVersion" yaml:"spdxVersion"`
}

// spdx3Basic is used to detect SPDX 3.0 JSON-LD format.
type spdx3Basic struct {
	Context interface{} `json:"@context"` // Can be string or array
}

// cdxbasic is a minimal struct for detecting CycloneDX JSON and XML files.
type cdxbasic struct {
	XMLNS     string `json:"-" xml:"xmlns,attr"`
	BOMFormat string `json:"bomFormat" xml:"-"`
}

// Detect inspects the contents of f and returns the detected SBOM spec, file
// format, and version. The caller must provide a seekable reader; the function
// rewinds to the start on exit. Returns SBOMSpecUnknown and an error if the
// format cannot be identified.
func Detect(f io.ReadSeeker) (SBOMSpec, FileFormat, FormatVersion, error) {
	defer f.Seek(0, io.SeekStart)

	f.Seek(0, io.SeekStart)

	// Check for SPDX 3.0 first (JSON-LD format with @context)
	var s3 spdx3Basic
	if err := json.NewDecoder(f).Decode(&s3); err == nil {
		contextStr := extractContextString(s3.Context)

		if strings.Contains(contextStr, spdxContextURL) {
			version := ""
			if strings.Contains(contextStr, spdxVersion301) {
				version = spdxVersionPrefix + spdxVersion301
			} else if strings.Contains(contextStr, "/"+spdxVersion30+"/") || strings.HasSuffix(contextStr, "/"+spdxVersion30) {
				version = spdxVersionPrefix + spdxVersion30
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

// IsSpdx3Version reports whether the given version string represents an SPDX
// 3.0.x format (e.g. "SPDX-3.0", "SPDX-3.0.1", "3.0", "3.0.1").
func IsSpdx3Version(version string) bool {
	// Handle formats like "SPDX-3.0", "SPDX-3.0.1", "3.0", "3.0.1"
	v := strings.ToLower(version)
	v = strings.TrimPrefix(v, strings.ToLower(spdxVersionPrefix))

	// Only support SPDX 3.0.x versions (3.0, 3.0.1, etc.)
	return strings.HasPrefix(v, spdxVersion30)
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
			if s, ok := item.(string); ok && strings.Contains(s, spdxContextURL) {
				return s
			}
		}
	}
	return ""
}

// DetectSbom opens the file at path and detects its SBOM spec, format, and
// version. It is a convenience wrapper around Detect.
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
