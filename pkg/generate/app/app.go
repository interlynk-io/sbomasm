// Copyright 2026 Interlynk.io
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

package app

import (
	"log"

	"gopkg.in/yaml.v2"
)

type author struct {
	Name  string `yaml:"name"`
	Email string `yaml:"email,omitempty"`
}

type license struct {
	Id string `yaml:"id"`
}

type supplier struct {
	Name  string `yaml:"name"`
	Email string `yaml:"email,omitempty"`
	URL   string `yaml:"url,omitempty"`
}

type checksum struct {
	Algorithm string `yaml:"algorithm"`
	Value     string `yaml:"value"`
}

type externalRef struct {
	Type    string `yaml:"type"`
	URL     string `yaml:"url"`
	Comment string `yaml:"comment,omitempty"`
}

type lifecycle struct {
	Phase string `yaml:"phase"`
}

type Output struct {
	Spec        string `yaml:"spec,omitempty"`
	SpecVersion string `yaml:"spec_version,omitempty"`
	FileFormat  string `yaml:"file_format,omitempty"`
}

type App struct {
	Name           string        `yaml:"name" json:"name"`
	Version        string        `yaml:"version" json:"version"`
	PrimaryPurpose string        `yaml:"primary_purpose" json:"primary_purpose"`
	Description    string        `yaml:"description,omitempty" json:"description,omitempty"`
	Author         []author      `yaml:"author,omitempty" json:"author,omitempty"`
	Purl           string        `yaml:"purl,omitempty" json:"purl,omitempty"`
	CPE            string        `yaml:"cpe,omitempty" json:"cpe,omitempty"`
	License        license       `yaml:"license,omitempty" json:"license,omitempty"`
	Supplier       supplier      `yaml:"supplier,omitempty" json:"supplier,omitempty"`
	Checksums      []checksum    `yaml:"checksum,omitempty" json:"checksum,omitempty"`
	Copyright      string        `yaml:"copyright,omitempty" json:"copyright,omitempty"`
	ExternalRefs   []externalRef `yaml:"external_refs,omitempty" json:"external_refs,omitempty"`
	Lifecycles     []lifecycle   `yaml:"lifecycles,omitempty" json:"lifecycles,omitempty"`
}

type Config struct {
	App    App    `yaml:"app"`
	Output Output `yaml:"output,omitempty"`
}

var DefaultConfig = Config{
	App: App{
		Name:           "[REQUIRED]",
		Version:        "[REQUIRED]",
		PrimaryPurpose: "[REQUIRED]",
		Description:    "[OPTIONAL]",
		Purl:           "[OPTIONAL]",
		CPE:            "[OPTIONAL]",
		License: license{
			Id: "[OPTIONAL]",
		},
		Supplier: supplier{
			Name:  "[OPTIONAL]",
			Email: "[OPTIONAL]",
			URL:   "[OPTIONAL]",
		},
		Checksums: []checksum{
			{
				Algorithm: "[OPTIONAL]",
				Value:     "[OPTIONAL]",
			},
		},
		Author: []author{
			{
				Name:  "[OPTIONAL]",
				Email: "[OPTIONAL]",
			},
		},
		Copyright: "[OPTIONAL]",
		ExternalRefs: []externalRef{
			{
				Type:    "[OPTIONAL]",
				URL:     "[OPTIONAL]",
				Comment: "[OPTIONAL]",
			},
		},
		Lifecycles: []lifecycle{
			{
				Phase: "[OPTIONAL]",
			},
		},
	},
	Output: Output{
		Spec:        "[OPTIONAL]",
		SpecVersion: "[OPTIONAL]",
		FileFormat:  "[OPTIONAL]",
	},
}

// DefaultConfigYaml: Creates a yaml output of the default config.
func DefaultAppYaml() []byte {
	yamlBytes, err := yaml.Marshal(&DefaultConfig)
	if err != nil {
		log.Fatal(err)
	}

	return yamlBytes
}
