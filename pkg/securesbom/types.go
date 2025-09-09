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
	"net/http"
	"time"
)

// Config holds configuration for the Secure SBOM API client
type Config struct {
	BaseURL    string
	APIKey     string
	HTTPClient HTTPClient
	Timeout    time.Duration
	UserAgent  string
}

type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// SecureSBOM Keys

type GenerateKeyCMDResponse struct {
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	Algorithm string    `json:"algorithm"`
	PublicKey string    `json:"public_key,omitempty"`
}

type KeyListResponse struct {
	Keys []GenerateKeyCMDResponse `json:"keys"`
}

type ListKeysAPIResponse struct {
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	Algorithm string    `json:"algorithm"`
}

type GenerateKeyAPIReponse struct {
	KeyID     string `json:"key_id"`
	PublicKey string `json:"public_key"`
}

// Signing

// intentenoly do not define a type for a sign result since we need to support many different types of sboms/reponses
type SignResultAPIResponse map[string]interface{}

// verification

type VerifyResultCMDResponse struct {
	Valid     bool      `json:"valid"`
	Message   string    `json:"message,omitempty"`
	KeyID     string    `json:"key_id,omitempty"`
	Algorithm string    `json:"algorithm,omitempty"`
	Timestamp time.Time `json:"timestamp,omitempty"`
}

type VerifyResultAPIResponse struct {
	Message   string `json:"message"`
	KeyID     string `json:"key_id"`
	Algorithm string `json:"algorithm"`
}
