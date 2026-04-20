// Copyright 2026 Interlynk.io
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
	"testing"

	"github.com/rogpeppe/go-internal/testscript"
)

// TestSbomasmGenerateSBOM drives integration tests that verify every feature
// documented in docs/spec/generate-sbom.md. Each testdata/generate_sbom/*.txt
// file is a self-contained scenario using embedded fixtures. The scripts shell
// out to:
//   - sbomasm  (registered by TestMain in edit_test.go)
//   - jq       (from host PATH)
//   - sbomqs   (from host PATH, used by the NTIA profile scenarios)
//
// Scenarios that are expected to fail today (because the implementation has a
// spec gap) are tagged with a "# EXPECTED FAILURE:" comment line at the top,
// then use negated assertions (`! exec ...` or `! grep ...`) to capture the
// current behaviour. When a gap is fixed, the assertion flips.
func TestSbomasmGenerateSBOM(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode.")
	}

	t.Parallel()
	testscript.Run(t, testscript.Params{
		Dir:                 "testdata/generate_sbom",
		RequireExplicitExec: true,
	})
}
