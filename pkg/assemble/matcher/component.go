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

package matcher

import (
	"strings"

	cydx "github.com/CycloneDX/cyclonedx-go"
	"github.com/spdx/tools-golang/spdx"
)

// UnifiedComponent wraps both CDX and SPDX components to provide a uniform interface
type UnifiedComponent struct {
	cdxComp *cydx.Component
	spdxPkg *spdx.Package
	format  string // "cdx" or "spdx"
}

// NewCDXComponent creates a UnifiedComponent from a CycloneDX component
func NewCDXComponent(comp *cydx.Component) Component {
	return &UnifiedComponent{
		cdxComp: comp,
		format:  "cdx",
	}
}

// NewSPDXComponent creates a UnifiedComponent from an SPDX package
func NewSPDXComponent(pkg *spdx.Package) Component {
	return &UnifiedComponent{
		spdxPkg: pkg,
		format:  "spdx",
	}
}

// GetPurl returns the package URL of the component
func (c *UnifiedComponent) GetPurl() string {
	if c.IsCDX() && c.cdxComp != nil {
		return c.cdxComp.PackageURL
	}
	if c.IsSPDX() && c.spdxPkg != nil {
		// SPDX stores purls in ExternalRefs
		for _, ref := range c.spdxPkg.PackageExternalReferences {
			if ref.RefType == "purl" || ref.Category == "PACKAGE-MANAGER" {
				return ref.Locator
			}
		}
	}
	return ""
}

// GetCPE returns the CPE of the component
func (c *UnifiedComponent) GetCPE() string {
	if c.IsCDX() && c.cdxComp != nil {
		return c.cdxComp.CPE
	}
	if c.IsSPDX() && c.spdxPkg != nil {
		// SPDX stores CPEs in ExternalRefs
		for _, ref := range c.spdxPkg.PackageExternalReferences {
			if ref.RefType == "cpe22Type" || ref.RefType == "cpe23Type" {
				return ref.Locator
			}
		}
	}
	return ""
}

// GetName returns the name of the component
func (c *UnifiedComponent) GetName() string {
	if c.IsCDX() && c.cdxComp != nil {
		return c.cdxComp.Name
	}
	if c.IsSPDX() && c.spdxPkg != nil {
		return c.spdxPkg.PackageName
	}
	return ""
}

// GetVersion returns the version of the component
func (c *UnifiedComponent) GetVersion() string {
	if c.IsCDX() && c.cdxComp != nil {
		return c.cdxComp.Version
	}
	if c.IsSPDX() && c.spdxPkg != nil {
		return c.spdxPkg.PackageVersion
	}
	return ""
}

// GetType returns the type of the component
func (c *UnifiedComponent) GetType() string {
	if c.IsCDX() && c.cdxComp != nil {
		return string(c.cdxComp.Type)
	}
	if c.IsSPDX() && c.spdxPkg != nil {
		// Map SPDX primary package purpose to CDX-like types
		purpose := strings.ToLower(c.spdxPkg.PrimaryPackagePurpose)
		switch purpose {
		case "application":
			return "application"
		case "framework":
			return "framework"
		case "library":
			return "library"
		case "container":
			return "container"
		case "operating-system":
			return "operating-system"
		case "device":
			return "device"
		case "firmware":
			return "firmware"
		case "file":
			return "file"
		default:
			return "library" // default fallback
		}
	}
	return ""
}

// IsCDX returns true if this is a CycloneDX component
func (c *UnifiedComponent) IsCDX() bool {
	return c.format == "cdx"
}

// IsSPDX returns true if this is an SPDX package
func (c *UnifiedComponent) IsSPDX() bool {
	return c.format == "spdx"
}

// GetOriginal returns the original component (either *cydx.Component or *spdx.Package)
func (c *UnifiedComponent) GetOriginal() interface{} {
	if c.IsCDX() {
		return c.cdxComp
	}
	if c.IsSPDX() {
		return c.spdxPkg
	}
	return nil
}