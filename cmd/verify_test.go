// Copyright 2025 Interlynk.io and Contributors
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadSignatureInput(t *testing.T) {
	signaturePayload := `{"algorithm":"ES256","detached":true,"sbom_type":"spdx","signature_b64":"MEQCID8yI8pYVaduL"}`
	signatureFile := filepath.Join(t.TempDir(), "signature.json")
	if err := os.WriteFile(signatureFile, []byte(signaturePayload+"\n"), 0600); err != nil {
		t.Fatalf("failed to write signature fixture: %v", err)
	}

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "empty signature",
			input:    "",
			expected: "",
		},
		{
			name:     "raw signature",
			input:    "MEQCID8yI8pYVaduL",
			expected: "MEQCID8yI8pYVaduL",
		},
		{
			name:     "json signature payload",
			input:    signaturePayload,
			expected: signaturePayload,
		},
		{
			name:     "json string signature payload",
			input:    `"MEQCID8yI8pYVaduL"`,
			expected: `"MEQCID8yI8pYVaduL"`,
		},
		{
			name:     "signature payload file",
			input:    signatureFile,
			expected: signaturePayload,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := loadSignatureInput(tt.input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if result != tt.expected {
				t.Fatalf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestLoadSignatureInputRejectsDirectory(t *testing.T) {
	_, err := loadSignatureInput(t.TempDir())
	if err == nil {
		t.Fatal("expected directory input to fail")
	}
}
