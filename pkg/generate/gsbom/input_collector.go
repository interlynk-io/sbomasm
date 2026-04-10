// Copyright 2026 Interlynk.io
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package gsbom

import (
	"fmt"
	"os"
	"path/filepath"
)

// CollectInputFiles collects input component files based on the provided parameters.
// It supports both explicit input files and recursive collection from a specified path.
// It returns a list of collected file paths and any warnings encountered during the process.
func CollectInputFiles(params *GenerateSBOMParams) ([]string, []error) {
	var files []string
	var warnings []error

	// 1. COllect explicit inputs FIRST
	files = append(files, params.InputFiles...)

	// 2. Handle recurse if RecursePath is provided
	if params.RecursePath != "" {
		err := filepath.Walk(params.RecursePath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				warnings = append(warnings, fmt.Errorf("error accessing path %s: %v", path, err))
				return nil
			}

			if info.IsDir() {
				return nil
			}

			// Match filename
			if info.Name() == params.Filename {
				files = append(files, path)
			}

			return nil
		})

		if err != nil {
			warnings = append(warnings, err)
		}
	}

	return files, warnings
}
