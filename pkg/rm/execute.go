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
	"strings"

	cydx "github.com/CycloneDX/cyclonedx-go"
	"github.com/interlynk-io/sbomasm/pkg/logger"
	"github.com/interlynk-io/sbomasm/pkg/rm/types"
	"github.com/interlynk-io/sbomasm/pkg/sbom"
	"github.com/spdx/tools-golang/spdx"
)

type FieldOperationEngine struct {
	doc sbom.SBOMDocument
}

type FieldOperationComponentEngine struct {
	doc sbom.SBOMDocument
}
type ComponentsOperationEngine struct {
	doc sbom.SBOMDocument
}

func (c *FieldOperationComponentEngine) SelectComponents(ctx context.Context, params *types.RmParams) ([]interface{}, error) {
	log := logger.FromContext(ctx)

	log.Debugf("Selecting components")

	var result []interface{}

	switch c.doc.SpecType() {
	case string(sbom.SBOMSpecSPDX):
		raw, ok := c.doc.Document().(*spdx.Document)
		if !ok {
			return nil, fmt.Errorf("unexpected SPDX document type")
		}

		if params.AllComponents {
			for _, pkg := range raw.Packages {
				result = append(result, pkg)
			}
			log.Debugf("Selected all components from SPDX document")
			return result, nil
		}

		name := strings.TrimSpace(params.ComponentName)
		version := strings.TrimSpace(params.ComponentVersion)
		if name == "" || version == "" {
			return nil, fmt.Errorf("component name and version are required unless --all-components is set")
		}

		for _, pkg := range raw.Packages {
			if strings.EqualFold(pkg.PackageName, name) && strings.EqualFold(pkg.PackageVersion, version) {
				result = append(result, pkg)
				break
			}
		}
		return result, nil

	case string(sbom.SBOMSpecCDX):
		raw, ok := c.doc.Document().(*cydx.BOM)
		if !ok {
			return nil, fmt.Errorf("unexpected CycloneDX BOM type")
		}

		if raw.Components == nil {
			return nil, nil
		}

		if params.AllComponents {
			log.Debugf("Selecting all components from CycloneDX BOM")
			if raw.Metadata.Component != nil {
				result = append(result, raw.Metadata.Component)
			}

			for i := range *raw.Components {
				result = append(result, &(*raw.Components)[i])
			}
			return result, nil
		}

		name := strings.TrimSpace(params.ComponentName)
		version := strings.TrimSpace(params.ComponentVersion)
		if name == "" || version == "" {
			return nil, fmt.Errorf("component name and version are required unless --all-components is set")
		}

		if raw.Metadata.Component != nil && strings.EqualFold(raw.Metadata.Component.Name, name) && strings.EqualFold(raw.Metadata.Component.Version, version) {
			result = append(result, raw.Metadata.Component)
		}
		if raw.Components != nil {
			for i := range *raw.Components {
				comp := &(*raw.Components)[i]
				if strings.EqualFold(comp.Name, name) && strings.EqualFold(comp.Version, version) {
					result = append(result, comp)
					break
				}
			}
		}
		return result, nil

	default:
		return nil, fmt.Errorf("unsupported spec type: %s", c.doc.SpecType())
	}
}

func (f *FieldOperationEngine) Execute(ctx context.Context, params *types.RmParams) error {
	log := logger.FromContext(ctx)
	log.Debugf("Executing field removal")
	if f.doc.Document() == nil {
		return nil
	}

	spec, scope, field := f.doc.SpecType(), strings.ToLower(params.Scope), strings.ToLower(params.Field)

	key := fmt.Sprintf("%s:%s:%s", strings.ToLower(spec), scope, field)
	log.Debugf("Handler Key: %s", key)
	handler, ok := handlerRegistry[key]
	if !ok {
		return fmt.Errorf("no handler registered for key: %s", key)
	}

	// Select
	selected, err := handler.Select(params)
	if err != nil {
		return err
	}

	if len(selected) == 0 {
		log.Debugf("No matching entries found.")
		return nil
	}

	// Filter
	targets, err := handler.Filter(selected, params)
	if err != nil {
		return err
	}

	if len(targets) == 0 {
		log.Debugf("No matching entries found.")
		return nil
	}

	// Summary or Dry-run
	if params.Summary {
		handler.Summary(selected)
		return nil
	}
	if params.DryRun {
		log.Infof("Dry-run: matched entries:")
		for _, entry := range targets {
			fmt.Printf("  - %v\n", entry)
		}
		return nil
	}

	// Remove
	return handler.Remove(targets, params)
}

func (c *ComponentsOperationEngine) Execute(ctx context.Context, params *types.RmParams) error {
	log := logger.FromContext(ctx)
	log.Debugf("Executing components removal process")

	// Step 1: Select components based on filter criteria
	selectedComponents, err := c.selectComponents(ctx, params)
	if err != nil {
		return fmt.Errorf("error selecting components: %w", err)
	}

	// Step 2: Find corresponding dependencies
	selectedDeps, err := c.findDependenciesForComponents(ctx, selectedComponents)
	if err != nil {
		return fmt.Errorf("error selecting dependencies: %w", err)
	}

	// Step 3: Remove components
	if err := c.removeComponents(ctx, selectedComponents); err != nil {
		return fmt.Errorf("error removing components: %w", err)
	}

	// Step 4: Remove dependencies
	if err := c.removeDependencies(ctx, selectedDeps); err != nil {
		return fmt.Errorf("error removing dependencies: %w", err)
	}

	return nil
}
