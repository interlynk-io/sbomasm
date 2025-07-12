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

type FieldOperationEngine struct {
	doc sbom.SBOMDocument
}

func (f *FieldOperationEngine) Execute(ctx context.Context, params *types.RmParams) error {
	if f.doc.Raw() == nil {
		return nil
	}

	selected, err := f.doc.Select(params)
	if err != nil {
		return err
	}

	targets, err := f.doc.Filter(selected, params)
	if err != nil {
		return err
	}

	if len(targets) == 0 {
		fmt.Println("No matching fields found.")
		return nil
	}

	if params.DryRun {
		fmt.Println("Dry-run mode:")
		for _, entry := range selected {
			fmt.Printf("  - %v\n", entry)
		}
		return nil
	}

	if params.Summary {
		f.doc.Summary(params.Field, selected)
		return nil
	}

	return f.doc.Remove(targets, params)
}
