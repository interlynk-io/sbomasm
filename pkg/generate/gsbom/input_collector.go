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

// CollectInputFiles performs the following steps:
// - Appends any explicitly provided input files to the list.
// - If a RecursePath is provided, it walks through the directory tree starting from that path.
//   - For each file encountered, it checks if the filename matches the specified Filename (e.g., ".components.json").
//   - If a match is found, the file path is added to the list of files.
//   - Any errors encountered while accessing paths are collected as warnings.
//
// - Finally, it returns the list of collected file paths and any warnings.
func CollectInputFiles(params *GenerateSBOMParams) ([]string, []error) {
	var files []string
	var errors []error

	// 1. Collect explicit inputs FIRST
	files = append(files, params.InputFiles...)

	// 2. Handle recurse if RecursePath is provided
	if params.RecursePath != "" {
		err := filepath.Walk(params.RecursePath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				errors = append(errors, fmt.Errorf("error accessing path %s: %v", path, err))
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
			errors = append(errors, err)
		}
	}

	return files, errors
}
