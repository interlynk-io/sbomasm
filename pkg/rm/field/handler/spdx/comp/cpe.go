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
	"github.com/interlynk-io/sbomasm/pkg/rm/field/spdx"
	"github.com/interlynk-io/sbomasm/pkg/rm/types"
	spdxdoc "github.com/spdx/tools-golang/spdx"
)

type SpdxComponentCpeHandler struct {
	Doc *spdxdoc.Document
}

func (h *SpdxComponentCpeHandler) Select(params *types.RmParams) ([]interface{}, error) {
	return spdx.SelectCpeFromComponent(h.Doc, params)
}

func (h *SpdxComponentCpeHandler) Filter(selected []interface{}, params *types.RmParams) ([]interface{}, error) {
	return spdx.FilterCpeFromComponent(h.Doc, selected, params)
}

func (h *SpdxComponentCpeHandler) Remove(targets []interface{}, params *types.RmParams) error {
	return spdx.RemoveCpeFromComponent(h.Doc, targets, params)
}

func (h *SpdxComponentCpeHandler) Summary(selected []interface{}) {
	spdx.RenderSummaryCpeFromComponent(selected)
}
