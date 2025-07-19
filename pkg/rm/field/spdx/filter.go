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

package spdx

import (
	"fmt"
	"strings"

	"github.com/interlynk-io/sbomasm/pkg/rm/types"
	"github.com/spdx/tools-golang/spdx"
)

func FilterAuthorFromMetadata(allAuthors []interface{}, params *types.RmParams) ([]interface{}, error) {
	var filteredAuthors []interface{}

	for _, s := range allAuthors {
		fmt.Println("Processing author entry:", s)
		author, ok := s.(spdx.Creator)
		if !ok || author.CreatorType != "Person" {
			fmt.Println("Skipping non-author entry:", s)
			continue
		}

		match := false
		switch {
		case params.IsKeyAndValuePresent:
			match = strings.Contains(author.Creator, params.Key) && strings.Contains(author.Creator, params.Value)
		case params.IsKeyPresent:
			match = strings.Contains(author.Creator, params.Key)
		case params.IsValuePresent:
			match = strings.Contains(author.Creator, params.Value)
		case params.All || (!params.IsKeyPresent && !params.IsValuePresent):
			match = true
		}

		if match {
			filteredAuthors = append(filteredAuthors, author)
		}
	}

	fmt.Println("Filtered SPDX authors:", filteredAuthors)
	return filteredAuthors, nil
}

func FilterLicenseFromMetadata(allLicenses []interface{}, params *types.RmParams) ([]interface{}, error) {
	var filteredLicenses []interface{}

	for _, s := range allLicenses {
		licenseStr, ok := s.(string)
		if !ok {
			continue
		}
		if params.IsKeyAndValuePresent {
			if strings.Contains(licenseStr, params.Key) && strings.Contains(licenseStr, params.Value) {
				filteredLicenses = append(filteredLicenses, licenseStr)
			}
		} else if params.IsKeyPresent {
			if strings.Contains(licenseStr, params.Key) {
				filteredLicenses = append(filteredLicenses, licenseStr)
			}
		} else if params.IsValuePresent {
			if strings.Contains(licenseStr, params.Value) {
				filteredLicenses = append(filteredLicenses, licenseStr)
			}
		} else if params.All || (!params.IsKeyPresent && !params.IsValuePresent) {
			filteredLicenses = append(filteredLicenses, licenseStr)
		}
	}
	return filteredLicenses, nil
}

func FilterLifecycleFromMetadata(allLifecycles []interface{}, params *types.RmParams) ([]interface{}, error) {
	var filteredLifecycles []interface{}

	for _, s := range allLifecycles {
		lifecycle, ok := s.(string)
		if !ok {
			continue
		}
		if params.IsKeyAndValuePresent {
			if strings.Contains(lifecycle, params.Key) && strings.Contains(lifecycle, params.Value) {
				filteredLifecycles = append(filteredLifecycles, lifecycle)
			}
		} else if params.IsKeyPresent && strings.Contains(lifecycle, params.Key) {
			filteredLifecycles = append(filteredLifecycles, lifecycle)
		} else if params.IsValuePresent && strings.Contains(lifecycle, params.Value) {
			filteredLifecycles = append(filteredLifecycles, lifecycle)
		} else if params.All || (!params.IsKeyPresent && !params.IsValuePresent) {
			filteredLifecycles = append(filteredLifecycles, lifecycle)
		}
	}

	return filteredLifecycles, nil
}

func FilterSupplierFromMetadata(allSuppliers []interface{}, params *types.RmParams) ([]interface{}, error) {
	var filteredSuppliers []interface{}

	for _, s := range allSuppliers {
		creator, ok := s.(spdx.Creator)
		if !ok {
			continue
		}

		name := creator.Creator

		if params.IsKeyAndValuePresent && name == params.Key && creator.CreatorType == params.Value {
			filteredSuppliers = append(filteredSuppliers, creator)
		} else if params.IsKeyPresent && name == params.Key {
			filteredSuppliers = append(filteredSuppliers, creator)
		} else if params.IsValuePresent && creator.CreatorType == params.Value {
			filteredSuppliers = append(filteredSuppliers, creator)
		} else if params.All || (!params.IsKeyPresent && !params.IsValuePresent) {
			filteredSuppliers = append(filteredSuppliers, creator)
		}
	}

	return filteredSuppliers, nil
}

func FilterToolFromMetadata(allTools []interface{}, params *types.RmParams) ([]interface{}, error) {
	var filteredTools []interface{}

	for _, s := range allTools {
		creator, ok := s.(spdx.Creator)
		if !ok {
			continue
		}

		toolName := creator.Creator

		if params.IsKeyAndValuePresent && toolName == params.Key && creator.CreatorType == params.Value {
			filteredTools = append(filteredTools, creator)
		} else if params.IsKeyPresent && toolName == params.Key {
			filteredTools = append(filteredTools, creator)
		} else if params.IsValuePresent && creator.CreatorType == params.Value {
			filteredTools = append(filteredTools, creator)
		} else if params.All || (!params.IsKeyPresent && !params.IsValuePresent) {
			filteredTools = append(filteredTools, creator)
		}
	}

	fmt.Println("Filtered SPDX tools:", filteredTools)

	return filteredTools, nil
}

func FilterTimestampFromMetadata(allTimestamps []interface{}, params *types.RmParams) ([]interface{}, error) {
	var filteredTimestamps []interface{}

	for _, entry := range allTimestamps {
		timestamp, ok := entry.(string)
		if !ok {
			continue
		}

		filteredTimestamps = append(filteredTimestamps, timestamp)

	}

	fmt.Println("Filtered SPDX timestamps:", filteredTimestamps)
	return filteredTimestamps, nil
}
