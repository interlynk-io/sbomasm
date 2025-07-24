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

	"github.com/interlynk-io/sbomasm/pkg/logger"
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
	log := logger.FromContext(ctx)
	log.Debugf("Starting removal process with params: %+v", params)
	params.Ctx = &ctx

	switch params.Kind {
	case types.FieldRemoval:
		return fieldRemoval(ctx, sbomDoc, params)

	case types.ComponentRemoval:
		return componentsRemoval(ctx, sbomDoc, params)

	case types.DependencyRemoval:
		// TODO: Implement
		return fmt.Errorf("dependency removal not implemented yet")

	default:
		return fmt.Errorf("invalid removal kind: %s", params.Kind)
	}
}

func fieldRemoval(ctx context.Context, sbomDoc sbom.SBOMDocument, params *types.RmParams) error {
	log := logger.FromContext(ctx)
	log.Debugf("Executing field removal")

	engine := &FieldOperationEngine{doc: sbomDoc}

	switch params.Scope {

	case string(DOCUMENT):
		log.Debugf("Executing document field removal")
		return engine.ExecuteDocumentFieldRemoval(ctx, params)

	case string(COMPONENT):
		log.Debugf("Executing component field removal")
		return engine.ExecuteComponentFieldRemoval(ctx, params)

	case string(DEPENDENCY):
		log.Debugf("Executing dependency field removal")
		// return engine.ExecuteDependencyFieldRemoval(ctx, params)

	default:
		return fmt.Errorf("invalid scope for field removal: %s", params.Scope)
	}

	return nil
}

func componentsRemoval(ctx context.Context, sbomDoc sbom.SBOMDocument, params *types.RmParams) error {
	componentsRemoval := &ComponentsOperationEngine{
		doc: sbomDoc,
	}
	return componentsRemoval.Execute(ctx, params)
}
