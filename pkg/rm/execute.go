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
	"log"
	"strings"

	cydx "github.com/CycloneDX/cyclonedx-go"
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
	var result []interface{}

	switch c.doc.SpecType() {
	case string(sbom.SBOMSpecSPDX):
		raw, ok := c.doc.Raw().(*spdx.Document)
		if !ok {
			return nil, fmt.Errorf("unexpected SPDX document type")
		}

		if params.AllComponents {
			for _, pkg := range raw.Packages {
				result = append(result, pkg)
			}
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
		raw, ok := c.doc.Raw().(*cydx.BOM)
		if !ok {
			return nil, fmt.Errorf("unexpected CycloneDX BOM type")
		}

		if raw.Components == nil {
			return nil, nil
		}

		if params.AllComponents {
			for _, comp := range *raw.Components {
				result = append(result, comp)
			}
			return result, nil
		}

		name := strings.TrimSpace(params.ComponentName)
		version := strings.TrimSpace(params.ComponentVersion)
		if name == "" || version == "" {
			return nil, fmt.Errorf("component name and version are required unless --all-components is set")
		}

		for _, comp := range *raw.Components {
			if strings.EqualFold(comp.Name, name) && strings.EqualFold(comp.Version, version) {
				result = append(result, comp)
				break
			}
		}
		return result, nil

	default:
		return nil, fmt.Errorf("unsupported spec type: %s", c.doc.SpecType())
	}
}

func (f *FieldOperationEngine) Execute(ctx context.Context, params *types.RmParams) error {
	if f.doc.Raw() == nil {
		return nil
	}

	spec, scope, field := f.doc.SpecType(), strings.ToLower(params.Scope), strings.ToLower(params.Field)

	key := fmt.Sprintf("%s:%s:%s", strings.ToLower(spec), scope, field)
	fmt.Println("Handler Key:", key)
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
		fmt.Println("No matching entries found.")
		return nil
	}

	// Filter
	targets, err := handler.Filter(selected, params)
	if err != nil {
		return err
	}

	if len(targets) == 0 {
		fmt.Println("No matching entries found.")
		return nil
	}

	// Summary or Dry-run
	if params.Summary {
		handler.Summary(selected)
		return nil
	}
	if params.DryRun {
		fmt.Println("Dry-run: matched entries:")
		for _, entry := range targets {
			fmt.Printf("  - %v\n", entry)
		}
		return nil
	}

	// Remove
	return handler.Remove(targets, params)
}

func (c *ComponentsOperationEngine) Execute(ctx context.Context, params *types.RmParams) error {
	// Step 1: Select components based on filter criteria
	selectedComponents, err := c.selectComponents(ctx, params)
	if err != nil {
		return fmt.Errorf("error selecting components: %w", err)
	}

	// Step 2: Find corresponding dependencies
	selectedDeps, err := c.findDependenciesForComponents(selectedComponents)
	if err != nil {
		return fmt.Errorf("error selecting dependencies: %w", err)
	}
	// fmt.Println("Selected dependencies:", selectedDeps)

	// Step 3: Remove components
	if err := c.removeComponents(selectedComponents); err != nil {
		return fmt.Errorf("error removing components: %w", err)
	}

	// Step 4: Remove dependencies
	if err := c.removeDependencies(selectedDeps); err != nil {
		return fmt.Errorf("error removing dependencies: %w", err)
	}

	log.Printf("Removed %d components and %d dependencies", len(selectedComponents), len(selectedDeps))
	return nil
}
