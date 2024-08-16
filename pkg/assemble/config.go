// Copyright 2023 Interlynk.io
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
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/interlynk-io/sbomasm/pkg/assemble/cdx"
	"github.com/interlynk-io/sbomasm/pkg/logger"
	"github.com/samber/lo"
	"gopkg.in/yaml.v2"
)

const DEFAULT_OUTPUT_SPEC = "cyclonedx"
const DEFAULT_OUTPUT_SPEC_VERSION = "1.6"
const DEFAULT_OUTPUT_FILE_FORMAT = "json"
const DEFAULT_OUTPUT_LICENSE = "CC0-1.0"

type author struct {
	Name  string `yaml:"name"`
	Email string `yaml:"email,omitempty"`
	Phone string `yaml:"phone,omitempty"`
}

type license struct {
	Id         string `yaml:"id"`
	Expression string `yaml:"expression,omitempty"`
}

type supplier struct {
	Name  string `yaml:"name"`
	Email string `yaml:"email,omitempty"`
}

type checksum struct {
	Algorithm string `yaml:"algorithm"`
	Value     string `yaml:"value"`
}

type app struct {
	Name           string     `yaml:"name"`
	Version        string     `yaml:"version"`
	Description    string     `yaml:"description,omitempty"`
	Author         []author   `yaml:"author,omitempty"`
	PrimaryPurpose string     `yaml:"primary_purpose,omitempty"`
	Purl           string     `yaml:"purl,omitempty"`
	CPE            string     `yaml:"cpe,omitempty"`
	License        license    `yaml:"license,omitempty"`
	Supplier       supplier   `yaml:"supplier,omitempty"`
	Checksums      []checksum `yaml:"checksum,omitempty"`
	Copyright      string     `yaml:"copyright,omitempty"`
}

type output struct {
	Spec        string `yaml:"spec"`
	SpecVersion string `yaml:"spec_version"`
	FileFormat  string `yaml:"file_format"`
	file        string
}

type input struct {
	files []string
}

type assemble struct {
	IncludeDependencyGraph     bool `yaml:"include_dependency_graph"`
	IncludeComponents          bool `yaml:"include_components"`
	includeDuplicateComponents bool
	FlatMerge                  bool `yaml:"flat_merge"`
	HierarchicalMerge          bool `yaml:"hierarchical_merge"`
	AssemblyMerge              bool `yaml:"assembly_merge"`
}

type config struct {
	ctx      *context.Context
	App      app    `yaml:"app"`
	Output   output `yaml:"output"`
	input    input
	Assemble assemble `yaml:"assemble"`
}

var defaultConfig = config{
	App: app{
		Name:           "[REQUIRED]",
		Version:        "[REQUIRED]",
		Description:    "[OPTIONAL]",
		PrimaryPurpose: "[REQUIRED]",
		Purl:           "[OPTIONAL]",
		CPE:            "[OPTIONAL]",
		License: license{
			Id: "[OPTIONAL]",
		},
		Supplier: supplier{
			Name:  "[OPTIONAL]",
			Email: "[OPTIONAL]",
		},
		Checksums: []checksum{
			{Algorithm: "[OPTIONAL]", Value: "[OPTIONAL]"},
		},
		Author: []author{
			{Name: "[OPTIONAL]", Email: "[OPTIONAL]"},
		},
		Copyright: "[OPTIONAL]",
	},
	Output: output{
		Spec:        DEFAULT_OUTPUT_SPEC,
		SpecVersion: DEFAULT_OUTPUT_SPEC_VERSION,
		FileFormat:  DEFAULT_OUTPUT_FILE_FORMAT,
	},
	Assemble: assemble{
		FlatMerge:                  false,
		HierarchicalMerge:          true,
		AssemblyMerge:              false,
		IncludeComponents:          true,
		IncludeDependencyGraph:     true,
		includeDuplicateComponents: true,
	},
}

func DefaultConfig() {
	data, err := yaml.Marshal(&defaultConfig)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(data))
}

func newConfig() *config {
	return &config{
		Output: output{
			Spec:        DEFAULT_OUTPUT_SPEC,
			SpecVersion: DEFAULT_OUTPUT_SPEC_VERSION,
			FileFormat:  DEFAULT_OUTPUT_FILE_FORMAT,
		},
		Assemble: assemble{
			FlatMerge:                  false,
			HierarchicalMerge:          true,
			IncludeComponents:          true,
			IncludeDependencyGraph:     true,
			includeDuplicateComponents: true,
		},
	}
}

func (c *config) readAndMerge(p *Params) error {
	if p.ConfigPath != "" {

		yF, err := os.ReadFile(p.ConfigPath)
		if err != nil {
			return err
		}

		err = yaml.Unmarshal(yF, &c)
		if err != nil {
			return err
		}
	} else {

		c.Assemble.FlatMerge = p.FlatMerge
		c.Assemble.HierarchicalMerge = p.HierMerge
		c.Assemble.AssemblyMerge = p.AssemblyMerge
	}

	c.input.files = p.Input
	c.Output.file = p.Output
	c.ctx = p.Ctx

	//override default config with params
	if p.Name != "" {
		c.App.Name = strings.Trim(p.Name, " ")
	}

	if p.Version != "" {
		c.App.Version = strings.Trim(p.Version, " ")
	}

	if p.Type != "" {
		c.App.PrimaryPurpose = strings.Trim(p.Type, " ")
	}

	if p.Xml {
		c.Output.FileFormat = "xml"
	}

	if p.OutputSpec != "" {
		c.Output.Spec = strings.Trim(p.OutputSpec, " ")
	}

	if p.OutputSpecVersion != "" {
		c.Output.SpecVersion = strings.Trim(p.OutputSpecVersion, " ")
	}

	return nil
}

func (c *config) validate() error {
	if c == nil {
		return fmt.Errorf("config is not set")
	}

	log := logger.FromContext(*c.ctx)

	validValue := func(v string) bool {
		vl := strings.ToLower(v)
		if vl == "" || vl == "[required]" {
			return false
		}
		return true
	}

	sanitize := func(v string) string {
		if strings.ToLower(v) == "[optional]" {
			return ""
		}

		return strings.Trim(v, " ")
	}

	if !validValue(c.App.Name) {
		return fmt.Errorf("app name is not set")
	}
	c.App.Name = sanitize(c.App.Name)

	if !validValue(c.App.Version) {
		return fmt.Errorf("app version is not set")
	}
	c.App.Version = sanitize(c.App.Version)

	c.App.PrimaryPurpose = sanitize(c.App.PrimaryPurpose)
	c.App.Description = sanitize(c.App.Description)
	c.App.License.Id = sanitize(c.App.License.Id)
	c.App.Supplier.Name = sanitize(c.App.Supplier.Name)
	c.App.Supplier.Email = sanitize(c.App.Supplier.Email)
	c.App.Purl = sanitize(c.App.Purl)
	c.App.CPE = sanitize(c.App.CPE)
	c.App.Copyright = sanitize(c.App.Copyright)
	c.Output.Spec = sanitize(c.Output.Spec)
	c.Output.SpecVersion = sanitize(c.Output.SpecVersion)
	c.Output.FileFormat = sanitize(c.Output.FileFormat)

	for i := range c.App.Author {
		c.App.Author[i].Name = sanitize(c.App.Author[i].Name)
		c.App.Author[i].Email = sanitize(c.App.Author[i].Email)
	}

	for i := range c.App.Checksums {
		sAlgo := sanitize(c.App.Checksums[i].Algorithm)
		sValue := sanitize(c.App.Checksums[i].Value)

		if sAlgo == "" && sValue == "" {
			c.App.Checksums[i].Algorithm = sAlgo
			c.App.Checksums[i].Value = sValue
			continue
		}

		ok := cdx.IsSupportedChecksum(sAlgo, sValue)
		if ok {
			c.App.Checksums[i].Algorithm = strings.ToUpper(sAlgo)
			c.App.Checksums[i].Value = sValue
		} else {
			return fmt.Errorf("unsupported hash algorithm %s or value %x :: use one of these %+v", sAlgo, sValue, cdx.SupportedChecksums())
		}
	}

	if c.Output.Spec == "" && c.Output.SpecVersion == "" {
		c.Output.Spec = ""
		c.Output.SpecVersion = ""
	}

	if c.Output.FileFormat == "" {
		c.Output.FileFormat = DEFAULT_OUTPUT_FILE_FORMAT
	}

	if c.input.files == nil || len(c.input.files) == 0 {
		return fmt.Errorf("input files are not set")
	}

	if len(c.input.files) <= 1 {
		return fmt.Errorf("assembly requires more than one sbom file")
	}

	err := c.validateInputContent()
	if err != nil {
		return err
	}

	log.Debugf("config %+v", c)

	return nil
}

func (c *config) validateInputContent() error {
	log := logger.FromContext(*c.ctx)
	sha256 := func(path string) string {
		f, err := os.Open(path)
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()
		h := sha256.New()
		if _, err := io.Copy(h, f); err != nil {
			log.Fatal(err)
		}
		return string(h.Sum(nil))
	}

	sums := []string{}

	for _, v := range c.input.files {
		sum := sha256(v)
		log.Debugf("sha256 %s : %x", v, sum)
		sums = append(sums, sum)
	}

	uniqSums := lo.Uniq(sums)

	if len(sums) != len(uniqSums) {
		return fmt.Errorf("input sboms contain duplicate content %+v", c.input.files)
	}

	return nil
}
