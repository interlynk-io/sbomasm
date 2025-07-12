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

package sbom

import (
	cydx "github.com/CycloneDX/cyclonedx-go"
	"github.com/interlynk-io/sbomasm/pkg/rm/cdx"
	"github.com/interlynk-io/sbomasm/pkg/rm/types"
	"github.com/spdx/tools-golang/spdx/common"
)

type SBOMDocument interface {
	SpecType() string
	Raw() any
	Select(params *types.RmParams) ([]interface{}, error)
	Filter(selected []interface{}, params *types.RmParams) ([]interface{}, error)
	Remove(targets []interface{}, params *types.RmParams) error
	Summary(field string, selected []interface{})
}

type SPDXDocument struct {
	Doc common.AnyDocument
}

func (s *SPDXDocument) SpecType() string { return "spdx" }
func (s *SPDXDocument) Raw() any         { return s.Doc }
func (s *SPDXDocument) Select(params *types.RmParams) ([]interface{}, error) {
	// return spdx.SelectSPDXField(s.Doc, params)
	return nil, nil // TODO: Implement this
}

func (s *SPDXDocument) Filter(selected []interface{}, params *types.RmParams) ([]interface{}, error) {
	// return spdx.FilterSPDXField(s.Doc, selected, params)
	return nil, nil // TODO: Implement this
}

func (s *SPDXDocument) Summary(field string, selected []interface{}) {
	// spdx.RenderSPDXSummary(field, selected)
	// return nil, nil // TODO: Implement this
}

func (s *SPDXDocument) Remove(targets []interface{}, params *types.RmParams) error {
	// return spdx.RemoveSPDXField(s.Doc, targets, params)
	return nil // TODO: Implement this
}

type CycloneDXDocument struct {
	BOM *cydx.BOM
}

func (c *CycloneDXDocument) SpecType() string { return "cdx" }
func (c *CycloneDXDocument) Raw() any         { return c.BOM }

func (c *CycloneDXDocument) Select(params *types.RmParams) ([]interface{}, error) {
	return cdx.SelectCDXField(c.BOM, params)
}

func (c *CycloneDXDocument) Filter(selected []interface{}, params *types.RmParams) ([]interface{}, error) {
	return cdx.FilterCDXField(c.BOM, selected, params)
}

func (c *CycloneDXDocument) Summary(field string, selected []interface{}) {
	cdx.RenderCDXSummary(field, selected)
}

func (c *CycloneDXDocument) Remove(targets []interface{}, params *types.RmParams) error {
	return cdx.RemoveCDXField(c.BOM, targets, params)
}
