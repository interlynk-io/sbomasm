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

type App struct {
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

type Config struct {
	App App `yaml:"app"`
}

var DefaultConfig = Config{
	App: App{
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
}

// DefaultConfigYaml: Creates a yaml output of the default config.
func DefaultAppYaml() []byte {
	yamlBytes, err := yaml.Marshal(&DefaultConfig)
	if err != nil {
		log.Fatal(err)
	}

	return yamlBytes
}
