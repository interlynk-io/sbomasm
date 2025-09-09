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

package assemble

import (
	"fmt"
	"strings"

	"github.com/interlynk-io/sbomasm/pkg/assemble/cdx"
	"github.com/interlynk-io/sbomasm/pkg/assemble/spdx"
	"github.com/interlynk-io/sbomasm/pkg/logger"
	"github.com/interlynk-io/sbomasm/pkg/sbom"
	"github.com/samber/lo"
)

type combiner struct {
	c         *config
	finalSpec string
}

func newCombiner(c *config) *combiner {
	return &combiner{c: c}
}

func (c *combiner) combine() error {
	log := logger.FromContext(*c.c.ctx)

	if strings.EqualFold(c.finalSpec, string(sbom.SBOMSpecCDX)) {
		log.Debugf("combining %d CycloneDX sboms", len(c.c.input.files))
		ms := toCDXMergerSettings(c.c)

		err := cdx.Merge(ms)
		if err != nil {
			return err
		}
	}

	if strings.EqualFold(c.finalSpec, string(sbom.SBOMSpecSPDX)) {
		log.Debugf("combining %d SPDX sboms", len(c.c.input.files))

		ms := toSpdxMergerSettings(c.c)

		err := spdx.Merge(ms)
		if err != nil {
			return err
		}
	}

	return nil
}

func (c *combiner) canCombine() error {
	specs := []string{}

	for _, doc := range c.c.input.files {
		spec, _, err := sbom.DetectSbom(doc)
		if err != nil {
			return fmt.Errorf("unable to detect sbom format for %s: %v", doc, err)
		}
		specs = append(specs, string(spec))
	}

	// all input specs should be of the same type
	if len(lo.Uniq(specs)) != 1 {
		return fmt.Errorf("input sboms are not of the same type")
	}

	c.finalSpec = specs[0]

	return nil
}

func toCDXMergerSettings(c *config) *cdx.MergeSettings {
	ms := cdx.MergeSettings{}

	ms.Ctx = c.ctx

	ms.Assemble.FlatMerge = c.Assemble.FlatMerge
	ms.Assemble.HierarchicalMerge = c.Assemble.HierarchicalMerge
	ms.Assemble.AssemblyMerge = c.Assemble.AssemblyMerge
	ms.Assemble.AugmentMerge = c.Assemble.AugmentMerge
	ms.Assemble.PrimaryFile = c.Assemble.PrimaryFile
	ms.Assemble.MatchStrategy = c.Assemble.MatchStrategy
	ms.Assemble.MergeMode = c.Assemble.MergeMode
	ms.Assemble.IncludeComponents = c.Assemble.IncludeComponents
	ms.Assemble.IncludeDuplicateComponents = c.Assemble.includeDuplicateComponents
	ms.Assemble.IncludeDependencyGraph = c.Assemble.IncludeDependencyGraph

	ms.Input.Files = []string{}
	ms.Input.Files = append(ms.Input.Files, c.input.files...)

	ms.Output.File = c.Output.file
	ms.Output.Upload = c.Output.Upload
	ms.Output.UploadProjectID = c.Output.UploadProjectID
	ms.Output.Url = c.Output.Url
	ms.Output.ApiKey = c.Output.ApiKey
	ms.Output.FileFormat = c.Output.FileFormat
	ms.Output.Spec = c.Output.Spec
	ms.Output.SpecVersion = c.Output.SpecVersion

	ms.App.Name = c.App.Name
	ms.App.Version = c.App.Version
	ms.App.Description = c.App.Description
	ms.App.PrimaryPurpose = c.App.PrimaryPurpose
	ms.App.Purl = c.App.Purl
	ms.App.CPE = c.App.CPE
	ms.App.Copyright = c.App.Copyright
	ms.App.Supplier = cdx.Supplier{}
	ms.App.Supplier.Name = c.App.Supplier.Name
	ms.App.Supplier.Email = c.App.Supplier.Email

	ms.App.License = cdx.License{}
	ms.App.License.Id = c.App.License.Id
	ms.App.License.Expression = c.App.License.Expression

	ms.App.Authors = []cdx.Author{}
	for _, a := range c.App.Author {
		ms.App.Authors = append(ms.App.Authors, cdx.Author{
			Name:  a.Name,
			Email: a.Email,
			Phone: a.Phone,
		})
	}

	ms.App.Checksums = []cdx.Checksum{}
	for _, c := range c.App.Checksums {
		ms.App.Checksums = append(ms.App.Checksums, cdx.Checksum{
			Algorithm: c.Algorithm,
			Value:     c.Value,
		})
	}

	return &ms
}

func toSpdxMergerSettings(c *config) *spdx.MergeSettings {
	ms := spdx.MergeSettings{}

	ms.Ctx = c.ctx

	ms.Assemble.FlatMerge = c.Assemble.FlatMerge
	ms.Assemble.HierarchicalMerge = c.Assemble.HierarchicalMerge
	ms.Assemble.AssemblyMerge = c.Assemble.AssemblyMerge
	ms.Assemble.AugmentMerge = c.Assemble.AugmentMerge
	ms.Assemble.PrimaryFile = c.Assemble.PrimaryFile
	ms.Assemble.MatchStrategy = c.Assemble.MatchStrategy
	ms.Assemble.MergeMode = c.Assemble.MergeMode
	ms.Assemble.IncludeComponents = c.Assemble.IncludeComponents
	ms.Assemble.IncludeDuplicateComponents = c.Assemble.includeDuplicateComponents
	ms.Assemble.IncludeDependencyGraph = c.Assemble.IncludeDependencyGraph

	ms.Input.Files = []string{}
	ms.Input.Files = append(ms.Input.Files, c.input.files...)

	ms.Output.File = c.Output.file
	ms.Output.FileFormat = c.Output.FileFormat

	ms.App.Name = c.App.Name
	ms.App.Version = c.App.Version
	ms.App.Description = c.App.Description
	ms.App.PrimaryPurpose = c.App.PrimaryPurpose
	ms.App.Purl = c.App.Purl
	ms.App.CPE = c.App.CPE
	ms.App.Copyright = c.App.Copyright
	ms.App.Supplier = spdx.Supplier{}
	ms.App.Supplier.Name = c.App.Supplier.Name
	ms.App.Supplier.Email = c.App.Supplier.Email

	ms.App.License = spdx.License{}
	ms.App.License.Id = c.App.License.Id
	ms.App.License.Expression = c.App.License.Expression

	ms.App.Authors = []spdx.Author{}
	for _, a := range c.App.Author {
		ms.App.Authors = append(ms.App.Authors, spdx.Author{
			Name:  a.Name,
			Email: a.Email,
			Phone: a.Phone,
		})
	}

	ms.App.Checksums = []spdx.Checksum{}
	for _, c := range c.App.Checksums {
		ms.App.Checksums = append(ms.App.Checksums, spdx.Checksum{
			Algorithm: c.Algorithm,
			Value:     c.Value,
		})
	}

	return &ms
}
