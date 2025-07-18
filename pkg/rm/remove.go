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

package rm

import (
	"context"
	"fmt"

	"github.com/interlynk-io/sbomasm/pkg/rm/types"
	"github.com/interlynk-io/sbomasm/pkg/sbom"
)

type SCOPE string

const (
	DOCUMENT   SCOPE = "document"
	COMPONENT  SCOPE = "component"
	DEPENDENCY SCOPE = "dependency"
)

func Remove(ctx context.Context, sbomDoc sbom.SBOMDocument, params *types.RmParams) error {
	switch params.Kind {
	case types.FieldRemoval:
		return fieldRemoval(ctx, sbomDoc, params)

	case types.ComponentRemoval:
		return componentsRemoval(ctx, sbomDoc, params)
	case types.DependencyRemoval:
		// TODO: Implement
		return fmt.Errorf("dependency removal not implemented yet")
	default:
		// return sbom.ErrInvalidRemovalKind
		return fmt.Errorf("invalid removal kind: %s", params.Kind)
	}
}

func fieldRemoval(ctx context.Context, sbomDoc sbom.SBOMDocument, params *types.RmParams) error {
	fieldRemoval := &FieldOperationEngine{
		doc: sbomDoc,
	}

	return fieldRemoval.Execute(ctx, params)
}

func componentsRemoval(ctx context.Context, sbomDoc sbom.SBOMDocument, params *types.RmParams) error {
	componentsRemoval := &ComponentsOperationEngine{
		doc: sbomDoc,
	}
	return componentsRemoval.Execute(ctx, params)
}
