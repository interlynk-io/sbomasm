// Copyright 2025 Interlynk.io
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

package edit

import (
	"context"

	"github.com/interlynk-io/sbomasm/pkg/logger"
)

// EditParams represents the parameters for the edit command
type EditParams struct {
	Ctx *context.Context

	Input  string
	Output string

	Subject string
	Search  string

	Append  bool
	Missing bool
	Remove  bool

	Name        string
	Version     string
	Supplier    string
	Timestamp   bool
	Authors     []string
	Purl        string
	Cpe         string
	Licenses    []string
	Hashes      []string
	Tools       []string
	CopyRight   string
	Lifecycles  []string
	Description string
	Repository  string
	Type        string
}

func NewEditParams() *EditParams {
	return &EditParams{}
}

func Edit(eParams *EditParams) error {
	log := logger.FromContext(*eParams.Ctx)

	c, err := convertToConfigParams(eParams)
	if err != nil {
		return err
	}
	log.Debugf("config %+v", c)

	spec, format, err := detectSbom(eParams.Input)
	if err != nil {
		return err
	}
	log.Debugf("input sbom spec: %s format: %s", spec, format)

	if spec == "cyclonedx" {
		if err = cdxEdit(c); err != nil {
			return err
		}
	}

	if spec == "spdx" {
		if err = spdxEdit(c); err != nil {
			return err
		}
	}

	return nil
}
