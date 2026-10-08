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

package meta

import (
	"github.com/interlynk-io/sbomasm/v2/pkg/rm/field/spdx3"
	"github.com/interlynk-io/sbomasm/v2/pkg/rm/types"
	"github.com/interlynk-io/spdx-zen/parse"
)

// Spdx3DocRepositoryHandler removes externalRef (repository) entries from SpdxDocument
type Spdx3DocRepositoryHandler struct {
	Doc *parse.Document
}

func (h *Spdx3DocRepositoryHandler) Select(params *types.RmParams) ([]interface{}, error) {
	return spdx3.SelectRepositoryFromMetadata(*params.Ctx, h.Doc)
}

func (h *Spdx3DocRepositoryHandler) Filter(selected []interface{}, params *types.RmParams) ([]interface{}, error) {
	return spdx3.FilterRepositoryFromMetadata(selected, params)
}

func (h *Spdx3DocRepositoryHandler) Remove(targets []interface{}, params *types.RmParams) error {
	return spdx3.RemoveRepositoryFromMetadata(*params.Ctx, h.Doc, targets)
}

func (h *Spdx3DocRepositoryHandler) Summary(selected []interface{}) {
	spdx3.RenderSummaryRepositoryFromMetadata(selected)
}
