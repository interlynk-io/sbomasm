package gsbom

import (
	"fmt"
	"os"
	"path/filepath"
)

func CollectInputFiles(params *GenerateSBOMParams) ([]string, []error) {
	var files []string
	var warnings []error

	// 1. Add explicit inputs FIRST
	files = append(files, params.InputFiles...)

	// 2. Handle recurse
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
