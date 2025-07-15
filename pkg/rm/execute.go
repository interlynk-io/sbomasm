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

	"github.com/interlynk-io/sbomasm/pkg/rm/types"
	"github.com/interlynk-io/sbomasm/pkg/sbom"
)

type FieldOperationEngine struct {
	doc sbom.SBOMDocument
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
