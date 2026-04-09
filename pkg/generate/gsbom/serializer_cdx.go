// Copyright 2026 Interlynk.io
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package gsbom

import (
	"time"

	cydx "github.com/CycloneDX/cyclonedx-go"

	"io"
	"os"
)

func utcNowTime() string {
	location, _ := time.LoadLocation("UTC")
	locationTime := time.Now().In(location)
	return locationTime.Format(time.RFC3339)
}

func SerializeCycloneDX(bom *BOM, output string) error {
	out := cydx.NewBOM()

	// --- Metadata ---
	out.Metadata = &cydx.Metadata{}
	out.Metadata.Timestamp = utcNowTime()

	// Primary component
	pc := cydx.Component{
		Name:        bom.Artifact.Name,
		Version:     bom.Artifact.Version,
		Type:        cydx.ComponentTypeApplication,
		Description: bom.Artifact.Description,
		PackageURL:  bom.Artifact.PURL,
		CPE:         bom.Artifact.CPE,
		BOMRef:      bom.Artifact.Name + "@" + bom.Artifact.Version,
	}

	out.Metadata.Component = &pc

	// --- Components ---
	var comps []cydx.Component

	for _, c := range bom.Components {
		comp := cydx.Component{
			Name:       c.Name,
			Version:    c.Version,
			Type:       cydx.ComponentTypeLibrary,
			PackageURL: c.PURL,
			CPE:        c.CPE,
			BOMRef:     componentKey(c),
		}
		comps = append(comps, comp)
	}

	out.Components = &comps

	// --- Dependencies ---
	var deps []cydx.Dependency

	// 1. Parent → children
	for parent, children := range bom.Dependencies {
		d := cydx.Dependency{
			Ref: parent,
		}

		var childRefs []string
		for _, c := range children {
			childRefs = append(childRefs, c)
		}

		d.Dependencies = &childRefs
		deps = append(deps, d)
	}

	// 2. Primary → top-level components
	var topLevel []string
	for _, c := range bom.Components {
		if len(c.DependencyOf) == 0 {
			topLevel = append(topLevel, componentKey(c))
		}
	}

	deps = append(deps, cydx.Dependency{
		Ref:          pc.BOMRef,
		Dependencies: &topLevel,
	})

	out.Dependencies = &deps

	// --- Write ---
	var writer io.Writer

	if output == "" {
		writer = os.Stdout
	} else {
		f, err := os.Create(output)
		if err != nil {
			return err
		}
		defer f.Close()
		writer = f
	}

	encoder := cydx.NewBOMEncoder(writer, cydx.BOMFileFormatJSON)
	encoder.SetPretty(true)

	return encoder.Encode(out)
}
