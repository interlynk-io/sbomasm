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

type CdxDocLifecycleHandler struct {
	Bom *cydx.BOM
}

func (h *CdxDocLifecycleHandler) Select(params *types.RmParams) ([]interface{}, error) {
	return cdx.SelectLifecycleFromMetadata(h.Bom)
}

func (h *CdxDocLifecycleHandler) Filter(selected []interface{}, params *types.RmParams) ([]interface{}, error) {
	return cdx.FilterLifecycleFromMetadata(selected, params)
}

func (h *CdxDocLifecycleHandler) Remove(targets []interface{}, params *types.RmParams) error {
	return cdx.RemoveLifecycleFromMetadata(h.Bom, targets)
}

func (h *CdxDocLifecycleHandler) Summary(selected []interface{}) {
	cdx.RenderSummaryLifecycleFromMetadata(selected)
}
