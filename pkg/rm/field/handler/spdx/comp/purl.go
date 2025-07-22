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

type SpdxComponentPurlHandler struct {
	Doc *spdxdoc.Document
}

func (h *SpdxComponentPurlHandler) Select(params *types.RmParams) ([]interface{}, error) {
	return spdx.SelectPurlFromComponent(h.Doc, params)
}

func (h *SpdxComponentPurlHandler) Filter(selected []interface{}, params *types.RmParams) ([]interface{}, error) {
	return spdx.FilterPurlFromComponent(h.Doc, selected, params)
}

func (h *SpdxComponentPurlHandler) Remove(targets []interface{}, params *types.RmParams) error {
	return spdx.RemovePurlFromComponent(h.Doc, targets, params)
}

func (h *SpdxComponentPurlHandler) Summary(selected []interface{}) {
	spdx.RenderSummaryPurlFromComponent(selected)
}
