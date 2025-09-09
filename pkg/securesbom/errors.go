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

// APIError represents an error response from the API
type APIError struct {
	StatusCode int    `json:"status_code"`
	Message    string `json:"message"`
	Details    string `json:"details,omitempty"`
	RequestID  string `json:"request_id,omitempty"`
}

// APIErrorResponse represents error responses from the API
type APIErrorResponse struct {
	Error   string `json:"error,omitempty"`
	Message string `json:"message,omitempty"`
}