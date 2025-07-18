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
	cydx "github.com/CycloneDX/cyclonedx-go"
	"github.com/interlynk-io/sbomasm/pkg/rm/field/cdx"
	"github.com/interlynk-io/sbomasm/pkg/rm/types"
)

type CdxDocToolHandler struct {
	Bom *cydx.BOM
}

func (h *CdxDocToolHandler) Select(params *types.RmParams) ([]interface{}, error) {
	return cdx.SelectToolFromMetadata(h.Bom)
}

func (h *CdxDocToolHandler) Filter(selected []interface{}, params *types.RmParams) ([]interface{}, error) {
	return cdx.FilterToolFromMetadata(selected, params)
}

func (h *CdxDocToolHandler) Remove(targets []interface{}, params *types.RmParams) error {
	return cdx.RemoveToolFromMetadata(h.Bom, targets)
}

func (h *CdxDocToolHandler) Summary(selected []interface{}) {
	cdx.RenderSummaryToolFromMetadata(selected)
}
