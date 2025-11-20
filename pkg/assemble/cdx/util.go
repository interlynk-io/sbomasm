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

package cdx

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"time"

	cydx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/uuid"
	"github.com/interlynk-io/sbomasm/v2/pkg/logger"
	"github.com/interlynk-io/sbomasm/v2/pkg/sbom"
	"github.com/samber/lo"
	"sigs.k8s.io/release-utils/version"
)

var specVersionMap = map[string]cydx.SpecVersion{
	"1.4": cydx.SpecVersion1_4,
	"1.5": cydx.SpecVersion1_5,
	"1.6": cydx.SpecVersion1_6,
}

func validSpecVersion(specVersion string) bool {
	_, ok := specVersionMap[specVersion]
	return ok
}

func newSerialNumber() string {
	u := uuid.New().String()

	return fmt.Sprintf("urn:uuid:%s", u)
}

func newBomRef() string {
	u := uuid.New().String()

	return fmt.Sprintf("lynk:%s", u)
}

func cloneComp(c *cydx.Component) (*cydx.Component, error) {
	var newComp cydx.Component

	// Marshal the original component to JSON
	b, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}

	// Unmarshal into a map[string]interface{} to perform cleanup
	var tempMap map[string]interface{}
	if err := json.Unmarshal(b, &tempMap); err != nil {
		return nil, err
	}

	// Remove empty fields recursively
	cleanedUpMap := removeEmptyFields(tempMap)

	// Marshal the cleaned-up map back to JSON
	cleanedUpBytes, err := json.Marshal(cleanedUpMap)
	if err != nil {
		return nil, err
	}

	// Unmarshal the cleaned-up JSON back into a cydx.Component struct
	if err := json.Unmarshal(cleanedUpBytes, &newComp); err != nil {
		return nil, err
	}

	return &newComp, nil
}

func cloneService(s *cydx.Service) (*cydx.Service, error) {
	var newService cydx.Service
	b, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	json.Unmarshal(b, &newService)
	return &newService, nil
}

// Recursive function to remove empty fields, including empty objects and arrays
func removeEmptyFields(data interface{}) interface{} {
	switch v := data.(type) {
	case map[string]interface{}:
		// Loop through map and remove empty fields
		for key, value := range v {
			v[key] = removeEmptyFields(value)
			// Remove empty maps and slices
			if isEmptyValue(v[key]) {
				delete(v, key)
			}
		}
	case []interface{}:
		// Process arrays
		var newArray []interface{}
		for _, item := range v {
			item = removeEmptyFields(item)
			if !isEmptyValue(item) {
				newArray = append(newArray, item)
			}
		}
		return newArray
	}
	return data
}

// Helper function to determine if a value is considered "empty"
func isEmptyValue(v interface{}) bool {
	if v == nil {
		return true
	}
	val := reflect.ValueOf(v)
	switch val.Kind() {
	case reflect.Array, reflect.Slice, reflect.Map:
		return val.Len() == 0
	case reflect.Struct:
		return reflect.DeepEqual(v, reflect.Zero(val.Type()).Interface())
	case reflect.String:
		return v == ""
	}
	return false
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

	spec, format, err := sbom.Detect(f)
	if err != nil {
		return nil, err
	}

	log.Debugf("loading bom:%s spec:%s format:%s", path, spec, format)

	switch format {
	case sbom.FileFormatJSON:
		bom = new(cydx.BOM)
		decoder := cydx.NewBOMDecoder(f, cydx.BOMFileFormatJSON)
		if err = decoder.Decode(bom); err != nil {
			return nil, err
		}
	case sbom.FileFormatXML:
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

func buildToolList(in []*cydx.BOM) *cydx.ToolsChoice {
	tools := cydx.ToolsChoice{}

	tools.Services = &[]cydx.Service{}
	tools.Components = &[]cydx.Component{}

	*tools.Components = append(*tools.Components, cydx.Component{
		Type:        cydx.ComponentTypeApplication,
		Name:        "sbomasm",
		Version:     version.GetVersionInfo().GitVersion,
		Description: "Assembler & Editor for your sboms",
		Supplier: &cydx.OrganizationalEntity{
			Name:    "Interlynk",
			URL:     &[]string{"https://interlynk.io"},
			Contact: &[]cydx.OrganizationalContact{{Email: "support@interlynk.io"}},
		},
		Licenses: &cydx.Licenses{
			{
				License: &cydx.License{
					ID: "Apache-2.0",
				},
			},
		},
	})

	for _, bom := range in {
		if bom.Metadata != nil && bom.Metadata.Tools != nil && bom.Metadata.Tools.Tools != nil {
			for _, tool := range *bom.Metadata.Tools.Tools {
				*tools.Components = append(*tools.Components, cydx.Component{
					Type:    cydx.ComponentTypeApplication,
					Name:    tool.Name,
					Version: tool.Version,
					Supplier: &cydx.OrganizationalEntity{
						Name: tool.Vendor,
					},
				})
			}
		}

		if bom.Metadata != nil && bom.Metadata.Tools != nil && bom.Metadata.Tools.Components != nil {
			for _, tool := range *bom.Metadata.Tools.Components {
				comp, _ := cloneComp(&tool)
				*tools.Components = append(*tools.Components, *comp)
			}
		}

		if bom.Metadata != nil && bom.Metadata.Tools != nil && bom.Metadata.Tools.Services != nil {
			for _, service := range *bom.Metadata.Tools.Services {
				serv, _ := cloneService(&service)
				*tools.Services = append(*tools.Services, *serv)
			}
		}
	}

	uniqTools := lo.UniqBy(*tools.Components, func(c cydx.Component) string {
		return fmt.Sprintf("%s-%s", c.Name, c.Version)
	})

	uniqServices := lo.UniqBy(*tools.Services, func(s cydx.Service) string {
		return fmt.Sprintf("%s-%s", s.Name, s.Version)
	})

	tools.Components = &uniqTools
	tools.Services = &uniqServices

	return &tools
}

func buildComponentList(in []*cydx.BOM, cs *uniqueComponentService) []cydx.Component {
	finalList := []cydx.Component{}

	for _, bom := range in {
		for _, comp := range lo.FromPtr(bom.Components) {
			newComp, duplicate := cs.StoreAndCloneWithNewID(&comp)
			if !duplicate {
				finalList = append(finalList, *newComp)
			}
		}
	}
	return finalList
}

func buildPrimaryComponentList(in []*cydx.BOM, cs *uniqueComponentService) []cydx.Component {
	return lo.Map(in, func(bom *cydx.BOM, _ int) cydx.Component {
		if bom.Metadata != nil && bom.Metadata.Component != nil {
			newComp, duplicate := cs.StoreAndCloneWithNewID(bom.Metadata.Component)
			if !duplicate {
				return *newComp
			}
		}
		return cydx.Component{}
	})
}

func buildDependencyList(in []*cydx.BOM, cs *uniqueComponentService) []cydx.Dependency {
	return lo.Flatten(lo.Map(in, func(bom *cydx.BOM, _ int) []cydx.Dependency {
		newDeps := []cydx.Dependency{}
		for _, dep := range lo.FromPtr(bom.Dependencies) {
			nd := cydx.Dependency{}
			ref, found := cs.ResolveDepID(dep.Ref)
			if !found {
				continue
			}

			if len(lo.FromPtr(dep.Dependencies)) == 0 {
				continue
			}

			deps := cs.ResolveDepIDs(lo.FromPtr(dep.Dependencies))
			nd.Ref = ref
			nd.Dependencies = &deps
			newDeps = append(newDeps, nd)
		}
		return newDeps
	}))
}

// cloneVulnerability creates a deep copy of a vulnerability
func cloneVulnerability(v *cydx.Vulnerability) (*cydx.Vulnerability, error) {
	var newVuln cydx.Vulnerability

	// Marshal the original vulnerability to JSON
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}

	// Unmarshal into a map[string]interface{} to perform cleanup
	var tempMap map[string]interface{}
	if err := json.Unmarshal(b, &tempMap); err != nil {
		return nil, err
	}

	// Remove empty fields recursively
	cleanedUpMap := removeEmptyFields(tempMap)

	// Marshal the cleaned-up map back to JSON
	cleanedUpBytes, err := json.Marshal(cleanedUpMap)
	if err != nil {
		return nil, err
	}

	// Unmarshal the cleaned-up JSON back into a cydx.Vulnerability struct
	if err := json.Unmarshal(cleanedUpBytes, &newVuln); err != nil {
		return nil, err
	}

	return &newVuln, nil
}

// vulnerabilityKey generates a unique key for vulnerability deduplication
// based on vulnerability ID and source name
func vulnerabilityKey(v *cydx.Vulnerability) string {
	sourceName := ""
	if v.Source != nil && v.Source.Name != "" {
		sourceName = v.Source.Name
	}
	return fmt.Sprintf("%s:%s", v.ID, sourceName)
}

// updateVulnerabilityRefs updates all component references in a vulnerability's affects array
// to use the new component BOM-refs from the component service
func updateVulnerabilityRefs(v *cydx.Vulnerability, cs *uniqueComponentService) {
	if v.Affects == nil {
		return
	}

	affects := *v.Affects
	for i := range affects {
		if newRef, found := cs.ResolveDepID(affects[i].Ref); found {
			affects[i].Ref = newRef
		}
	}
}

// isVulnerabilityRelevant checks if a vulnerability affects any of the processed components
// processedComps is a map of old component BOM-ref to new component BOM-ref
func isVulnerabilityRelevant(v *cydx.Vulnerability, processedComps map[string]string) bool {
	if v.Affects == nil {
		return false
	}

	for _, affect := range *v.Affects {
		if _, found := processedComps[affect.Ref]; found {
			return true
		}
	}
	return false
}

// buildVulnerabilityList builds a deduplicated list of vulnerabilities from all input BOMs
// It clones vulnerabilities, updates component references, and generates new BOM-refs
func buildVulnerabilityList(in []*cydx.BOM, cs *uniqueComponentService) []cydx.Vulnerability {
	finalList := []cydx.Vulnerability{}
	seenVulns := make(map[string]bool)

	for _, bom := range in {
		if bom.Vulnerabilities == nil {
			continue
		}

		for _, vuln := range *bom.Vulnerabilities {
			// Generate unique key for deduplication (ID + Source)
			key := vulnerabilityKey(&vuln)

			// Skip if we've already seen this vulnerability (keep first occurrence)
			if seenVulns[key] {
				continue
			}
			seenVulns[key] = true

			// Clone the vulnerability
			newVuln, err := cloneVulnerability(&vuln)
			if err != nil {
				// Log error but continue processing
				continue
			}

			// Update component references in affects array
			updateVulnerabilityRefs(newVuln, cs)

			// Generate new unique BOM-ref
			newVuln.BOMRef = newBomRef()

			finalList = append(finalList, *newVuln)
		}
	}

	return finalList
}
