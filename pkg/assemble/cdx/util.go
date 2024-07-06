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

package cdx

import (
	"context"
	"fmt"
	"os"
	"time"

	cydx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/uuid"
	"github.com/interlynk-io/sbomasm/pkg/detect"
	"github.com/interlynk-io/sbomasm/pkg/logger"
	"github.com/mitchellh/copystructure"
	"github.com/mitchellh/hashstructure/v2"
	"sigs.k8s.io/release-utils/version"
)

func newSerialNumber() string {
	u := uuid.New().String()

	return fmt.Sprintf("urn:uuid:%s", u)
}

func newBomRef(obj interface{}) string {
	f, _ := hashstructure.Hash(obj, hashstructure.FormatV2, &hashstructure.HashOptions{
		ZeroNil:      true,
		SlicesAsSets: true,
	})

	return fmt.Sprintf("%x", f)
}

func cloneComp(c *cydx.Component) (*cydx.Component, error) {
	compCopy, err := copystructure.Copy(c)
	if err != nil {
		return nil, err
	}

	return compCopy.(*cydx.Component), nil
}

func loadBom(ctx context.Context, path string) (*cydx.BOM, error) {
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

func utcNowTime() string {
	location, _ := time.LoadLocation("UTC")
	locationTime := time.Now().In(location)
	return locationTime.Format(time.RFC3339)
}

func getAllTools(boms []*cydx.BOM) []cydx.Component {
	tools := []cydx.Component{}

	tools = append(tools, *toolInfo("sbomasm", version.GetVersionInfo().GitVersion, "Assembler for your sboms", "Interlynk", "https://interlynk.io", "support@interlynk.io", "Apache-2.0"))

	for _, bom := range boms {
		if bom.Metadata != nil && bom.Metadata.Tools != nil {
			for _, tool := range *bom.Metadata.Tools.Tools {
				tools = append(tools, *toolInfo(tool.Name, tool.Version, "", tool.Vendor, "", "", ""))
			}
		}

		if bom.Metadata != nil && bom.Metadata.Tools != nil && bom.Metadata.Tools.Components != nil {
			for _, tool := range *bom.Metadata.Tools.Components {
				tools = append(tools, *toolInfo(tool.Name, tool.Version, "", "", "", "", ""))
			}
		}
	}
	return tools
}

func toolInfo(name, version, desc, sName, sUrl, sEmail, sLicense string) *cydx.Component {
	return &cydx.Component{
		Type:        cydx.ComponentTypeApplication,
		Name:        name,
		Version:     version,
		Description: desc,
		Supplier: &cydx.OrganizationalEntity{
			Name:    sName,
			URL:     &[]string{sUrl},
			Contact: &[]cydx.OrganizationalContact{{Email: sEmail}},
		},
		Licenses: &cydx.Licenses{
			{
				License: &cydx.License{
					ID: sLicense,
				},
			},
		},
	}
}
