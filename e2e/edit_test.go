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

package e2e_edit_test

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/interlynk-io/sbomasm/v2/cmd"

	"github.com/rogpeppe/go-internal/testscript"
)

func TestSbomasmEdit(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode.")
	}

	t.Parallel()
	testscript.Run(t, testscript.Params{
		Dir:                 "testdata/edit",
		RequireExplicitExec: true,
		Setup: func(env *testscript.Env) error {
			// copy required files to the workspace
			if err := copyFile("testdata/edit/photon-lite.spdx.json", filepath.Join(env.WorkDir, "photon-lite.spdx.json")); err != nil {
				return err
			}
			if err := copyFile("testdata/edit/expected-output-lite.spdx.json", filepath.Join(env.WorkDir, "expected-output-lite.spdx.json")); err != nil {
				return err
			}

			return nil
		},
	})
}

func runSbomasm() int {
	cmd.Execute()
	return 0
}

func TestMain(m *testing.M) {
	exitCode := testscript.RunMain(m, map[string]func() int{
		"sbomasm": runSbomasm,
	})
	os.Exit(exitCode)
}

// Helper function to copy files
func copyFile(src, dst string) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	destFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destFile.Close()

	_, err = io.Copy(destFile, sourceFile)
	return err
}
