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

package securesbom

import (
	"encoding/json"
)

// GetSignatureValue returns the signature value as a string for convenience
func (sr SignResultAPIResponse) GetSignatureValue() string {
	if sig, ok := sr["signature"].(map[string]interface{}); ok {
		if value, ok := sig["value"].(string); ok {
			return value
		}
	}
	return ""
}

// GetSignatureAlgorithm returns the signature algorithm
func (sr SignResultAPIResponse) GetSignatureAlgorithm() string {
	if sig, ok := sr["signature"].(map[string]interface{}); ok {
		if alg, ok := sig["algorithm"].(string); ok {
			return alg
		}
	}
	return ""
}

// GetSignedSBOMBytes returns the complete signed SBOM as JSON bytes
func (sr SignResultAPIResponse) GetSignedSBOMBytes() ([]byte, error) {
	return json.Marshal(sr)
}

// HasSignature returns true if the SBOM contains a signature
func (sr SignResultAPIResponse) HasSignature() bool {
	_, ok := sr["signature"]
	return ok
}
