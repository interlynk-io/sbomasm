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

package comp

import (
	cydx "github.com/CycloneDX/cyclonedx-go"
	"github.com/interlynk-io/sbomasm/pkg/rm/field/cdx"
	"github.com/interlynk-io/sbomasm/pkg/rm/types"
)

type CdxComponentHashHandler struct {
	Bom *cydx.BOM
}

func (h *CdxComponentHashHandler) Select(params *types.RmParams) ([]interface{}, error) {
	return cdx.SelectHashFromComponent(h.Bom, params)
}

func (h *CdxComponentHashHandler) Filter(selected []interface{}, params *types.RmParams) ([]interface{}, error) {
	return cdx.FilterHashFromComponent(h.Bom, selected, params)
}

func (h *CdxComponentHashHandler) Remove(targets []interface{}, params *types.RmParams) error {
	return cdx.RemoveHashFromComponent(h.Bom, targets, params)
}

func (h *CdxComponentHashHandler) Summary(selected []interface{}) {
	// cdx.RenderSummaryHashFromComponent(selected)
}
