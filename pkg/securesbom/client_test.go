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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// MockHTTPClient implements HTTPClient interface for testing
type MockHTTPClient struct {
	DoFunc func(req *http.Request) (*http.Response, error)
}

func (m *MockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	if m.DoFunc != nil {
		return m.DoFunc(req)
	}
	return nil, fmt.Errorf("DoFunc not implemented")
}

// Helper function to create a mock HTTP response
func createMockResponse(statusCode int, body interface{}) *http.Response {
	var bodyReader io.ReadCloser

	if body != nil {
		switch v := body.(type) {
		case string:
			bodyReader = io.NopCloser(strings.NewReader(v))
		case []byte:
			bodyReader = io.NopCloser(bytes.NewReader(v))
		default:
			jsonBytes, _ := json.Marshal(v)
			bodyReader = io.NopCloser(bytes.NewReader(jsonBytes))
		}
	} else {
		bodyReader = io.NopCloser(strings.NewReader(""))
	}

	return &http.Response{
		StatusCode: statusCode,
		Body:       bodyReader,
		Header:     make(http.Header),
	}
}

func TestNewClient(t *testing.T) {
	tests := []struct {
		name        string
		config      *Config
		expectError bool
		errorMsg    string
	}{
		{
			name:        "nil config",
			config:      nil,
			expectError: true,
			errorMsg:    "config is required",
		},
		{
			name: "missing API key",
			config: &Config{
				BaseURL: "https://api.example.com",
			},
			expectError: true,
			errorMsg:    "APIKey is required",
		},
		{
			name: "missing base URL",
			config: &Config{
				APIKey: "test-key",
			},
			expectError: true,
			errorMsg:    "BaseURL is required",
		},
		{
			name: "invalid base URL",
			config: &Config{
				APIKey:  "test-key",
				BaseURL: "://invalid-url",
			},
			expectError: true,
			errorMsg:    "invalid BaseURL",
		},
		{
			name: "negative timeout",
			config: &Config{
				APIKey:  "test-key",
				BaseURL: "https://api.example.com",
				Timeout: -1 * time.Second,
			},
			expectError: true,
			errorMsg:    "Timeout cannot be negative",
		},
		{
			name: "valid config with defaults",
			config: &Config{
				APIKey:  "test-key",
				BaseURL: "https://api.example.com",
			},
			expectError: false,
		},
		{
			name: "valid config with custom values",
			config: &Config{
				APIKey:    "test-key",
				BaseURL:   "https://api.example.com",
				Timeout:   60 * time.Second,
				UserAgent: "custom-agent",
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewClient(tt.config)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
					return
				}
				if !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("expected error to contain %q, got %q", tt.errorMsg, err.Error())
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if client == nil {
				t.Error("expected client to be non-nil")
				return
			}

			// Check that defaults are applied
			if client.config.Timeout == 0 {
				t.Error("expected default timeout to be set")
			}
			if client.config.UserAgent == "" {
				t.Error("expected default user agent to be set")
			}
		})
	}
}

func TestClient_buildURL(t *testing.T) {
	client := &Client{
		config: &Config{
			BaseURL: "https://api.example.com",
		},
	}

	tests := []struct {
		name     string
		baseURL  string
		endpoint string
		expected string
	}{
		{
			name:     "simple endpoint",
			baseURL:  "https://api.example.com",
			endpoint: "/v0/keys",
			expected: "https://api.example.com/v0/keys",
		},
		{
			name:     "base URL with trailing slash",
			baseURL:  "https://api.example.com/",
			endpoint: "/v0/keys",
			expected: "https://api.example.com/v0/keys",
		},
		{
			name:     "endpoint without leading slash",
			baseURL:  "https://api.example.com",
			endpoint: "v0/keys",
			expected: "https://api.example.com/v0/keys",
		},
		{
			name:     "both with trailing/leading slashes",
			baseURL:  "https://api.example.com/",
			endpoint: "/v0/keys",
			expected: "https://api.example.com/v0/keys",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client.config.BaseURL = tt.baseURL
			result := client.buildURL(tt.endpoint)
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestClient_doRequest(t *testing.T) {
	tests := []struct {
		name         string
		method       string
		endpoint     string
		body         interface{}
		mockResponse *http.Response
		mockError    error
		expectError  bool
		errorType    string
	}{
		{
			name:         "successful GET request",
			method:       "GET",
			endpoint:     "/v0/keys",
			mockResponse: createMockResponse(200, `{"keys": []}`),
			expectError:  false,
		},
		{
			name:         "successful POST request with body",
			method:       "POST",
			endpoint:     "/v0/keys",
			body:         map[string]string{"name": "test"},
			mockResponse: createMockResponse(201, `{"id": "key-123"}`),
			expectError:  false,
		},
		{
			name:        "HTTP client error",
			method:      "GET",
			endpoint:    "/v0/keys",
			mockError:   fmt.Errorf("network error"),
			expectError: true,
			errorType:   "request failed",
		},
		{
			name:         "API error with structured response",
			method:       "GET",
			endpoint:     "/v0/keys",
			mockResponse: createMockResponse(400, map[string]string{"message": "Invalid request", "details": "Missing parameter"}),
			expectError:  true,
			errorType:    "*securesbom.APIError",
		},
		{
			name:         "API error with alternative error field",
			method:       "GET",
			endpoint:     "/v0/keys",
			mockResponse: createMockResponse(500, map[string]string{"error": "Internal server error"}),
			expectError:  true,
			errorType:    "*securesbom.APIError",
		},
		{
			name:         "API error without structured response",
			method:       "GET",
			endpoint:     "/v0/keys",
			mockResponse: createMockResponse(404, ""),
			expectError:  true,
			errorType:    "*securesbom.APIError",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := &MockHTTPClient{
				DoFunc: func(req *http.Request) (*http.Response, error) {
					// Verify request headers
					if req.Header.Get("x-api-key") != "test-key" {
						t.Error("expected x-api-key header to be set")
					}
					if req.Header.Get("User-Agent") != UserAgent {
						t.Error("expected User-Agent header to be set")
					}
					if req.Header.Get("Accept") != "application/json" {
						t.Error("expected Accept header to be set")
					}

					if tt.body != nil && req.Header.Get("Content-Type") != "application/json" {
						t.Error("expected Content-Type header to be set for requests with body")
					}

					if tt.mockError != nil {
						return nil, tt.mockError
					}
					return tt.mockResponse, nil
				},
			}

			client := &Client{
				config: &Config{
					APIKey:    "test-key",
					BaseURL:   "https://api.example.com",
					UserAgent: UserAgent,
				},
				httpClient: mockClient,
			}

			ctx := context.Background()
			resp, err := client.doRequest(ctx, tt.method, tt.endpoint, tt.body)

			if tt.expectError {
				if err == nil {
					t.Error("expected error but got none")
					return
				}

				if tt.errorType == "*securesbom.APIError" {
					var apiErr *APIError
					if !strings.Contains(fmt.Sprintf("%T", err), "APIError") {
						t.Errorf("expected APIError, got %T", err)
					} else {
						apiErr = err.(*APIError)
						if apiErr.StatusCode == 0 {
							t.Error("expected APIError to have StatusCode set")
						}
					}
				} else if !strings.Contains(err.Error(), tt.errorType) {
					t.Errorf("expected error to contain %q, got %q", tt.errorType, err.Error())
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if resp == nil {
				t.Error("expected response to be non-nil")
			}
		})
	}
}

func TestClient_HealthCheck(t *testing.T) {
	tests := []struct {
		name         string
		mockResponse *http.Response
		mockError    error
		expectError  bool
	}{
		{
			name:         "successful health check",
			mockResponse: createMockResponse(200, "OK"),
			expectError:  false,
		},
		{
			name:        "health check failure",
			mockError:   fmt.Errorf("connection refused"),
			expectError: true,
		},
		{
			name:         "health check API error",
			mockResponse: createMockResponse(503, "Service Unavailable"),
			expectError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := &MockHTTPClient{
				DoFunc: func(req *http.Request) (*http.Response, error) {
					expectedURL := "https://api.example.com/infra/healthcheck"
					if req.URL.String() != expectedURL {
						t.Errorf("expected URL %q, got %q", expectedURL, req.URL.String())
					}
					if req.Method != "GET" {
						t.Errorf("expected GET method, got %q", req.Method)
					}

					if tt.mockError != nil {
						return nil, tt.mockError
					}
					return tt.mockResponse, nil
				},
			}

			client := &Client{
				config: &Config{
					APIKey:    "test-key",
					BaseURL:   "https://api.example.com",
					UserAgent: UserAgent,
				},
				httpClient: mockClient,
			}

			ctx := context.Background()
			err := client.HealthCheck(ctx)

			if tt.expectError {
				if err == nil {
					t.Error("expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestClient_ListKeys(t *testing.T) {
	tests := []struct {
		name         string
		mockResponse *http.Response
		mockError    error
		expectError  bool
		expectedKeys int
	}{
		{
			name: "successful list keys",
			// Mock the actual API response format - array of apiKeyListItem
			mockResponse: createMockResponse(200, []map[string]interface{}{
				{
					"id":         "key-1",
					"created_at": "2023-01-01T12:00:00Z",
					"algorithm":  "ES256",
				},
				{
					"id":         "key-2",
					"created_at": "2023-01-02T12:00:00Z",
					"algorithm":  "ES256",
				},
			}),
			expectError:  false,
			expectedKeys: 2,
		},
		{
			name:        "request failure",
			mockError:   fmt.Errorf("network error"),
			expectError: true,
		},
		{
			name:         "invalid JSON response",
			mockResponse: createMockResponse(200, "invalid json"),
			expectError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := &MockHTTPClient{
				DoFunc: func(req *http.Request) (*http.Response, error) {
					expectedURL := "https://api.example.com/v0/keys?showpub=false"
					if req.URL.String() != expectedURL {
						t.Errorf("expected URL %q, got %q", expectedURL, req.URL.String())
					}
					if req.Method != "GET" {
						t.Errorf("expected GET method, got %q", req.Method)
					}

					if tt.mockError != nil {
						return nil, tt.mockError
					}
					return tt.mockResponse, nil
				},
			}

			client := &Client{
				config: &Config{
					APIKey:    "test-key",
					BaseURL:   "https://api.example.com",
					UserAgent: UserAgent,
				},
				httpClient: mockClient,
			}

			ctx := context.Background()
			result, err := client.ListKeys(ctx)

			if tt.expectError {
				if err == nil {
					t.Error("expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
					return
				}
				if result == nil {
					t.Error("expected result to be non-nil")
					return
				}
				if len(result.Keys) != tt.expectedKeys {
					t.Errorf("expected %d keys, got %d", tt.expectedKeys, len(result.Keys))
				}
			}
		})
	}
}

func TestClient_GenerateKey(t *testing.T) {
	tests := []struct {
		name         string
		mockResponse *http.Response
		mockError    error
		expectError  bool
	}{
		{
			name: "successful key generation",
			// Mock the actual API response format (apiGenerateKeyResponse)
			mockResponse: createMockResponse(200, map[string]interface{}{
				"key_id":     "key-123",
				"public_key": "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZI...\n-----END PUBLIC KEY-----",
			}),
			expectError: false,
		},
		{
			name:        "request failure",
			mockError:   fmt.Errorf("network error"),
			expectError: true,
		},
		{
			name:         "API error response",
			mockResponse: createMockResponse(400, map[string]string{"error": "invalid request"}),
			expectError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := &MockHTTPClient{
				DoFunc: func(req *http.Request) (*http.Response, error) {
					expectedURL := "https://api.example.com/v0/keys?alg=ES256"
					if req.URL.String() != expectedURL {
						t.Errorf("expected URL %q, got %q", expectedURL, req.URL.String())
					}

					if req.Method != "POST" {
						t.Errorf("expected POST method, got %q", req.Method)
					}

					if tt.mockError != nil {
						return nil, tt.mockError
					}
					return tt.mockResponse, nil
				},
			}

			client := &Client{
				config: &Config{
					APIKey:    "test-key",
					BaseURL:   "https://api.example.com",
					UserAgent: UserAgent,
				},
				httpClient: mockClient,
			}

			ctx := context.Background()
			result, err := client.GenerateKey(ctx)

			if tt.expectError {
				if err == nil {
					t.Error("expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
					return
				}
				if result == nil {
					t.Error("expected result to be non-nil")
					return
				}
				if result.ID == "" {
					t.Error("expected key ID to be non-empty")
				}
				if result.Algorithm != "ES256" {
					t.Errorf("expected algorithm to be 'ES256', got %q", result.Algorithm)
				}
				if result.CreatedAt.IsZero() {
					t.Error("expected CreatedAt to be set")
				}
			}
		})
	}
}

func TestClient_GetPublicKey(t *testing.T) {
	pemKey := "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...\n-----END PUBLIC KEY-----"

	tests := []struct {
		name         string
		keyID        string
		mockResponse *http.Response
		mockError    error
		expectError  bool
		expectedPEM  string
	}{
		{
			name:         "successful get public key",
			keyID:        "key-123",
			mockResponse: createMockResponse(200, pemKey),
			expectError:  false,
			expectedPEM:  pemKey,
		},
		{
			name:        "empty key ID",
			keyID:       "",
			expectError: true,
		},
		{
			name:        "request failure",
			keyID:       "key-123",
			mockError:   fmt.Errorf("network error"),
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := &MockHTTPClient{
				DoFunc: func(req *http.Request) (*http.Response, error) {
					if tt.keyID != "" {
						expectedURL := fmt.Sprintf("https://api.example.com/v0/keys/%s/public.pem", tt.keyID)
						if req.URL.String() != expectedURL {
							t.Errorf("expected URL %q, got %q", expectedURL, req.URL.String())
						}
					}
					if req.Method != "GET" {
						t.Errorf("expected GET method, got %q", req.Method)
					}

					if tt.mockError != nil {
						return nil, tt.mockError
					}
					return tt.mockResponse, nil
				},
			}

			client := &Client{
				config: &Config{
					APIKey:    "test-key",
					BaseURL:   "https://api.example.com",
					UserAgent: UserAgent,
				},
				httpClient: mockClient,
			}

			ctx := context.Background()
			result, err := client.GetPublicKey(ctx, tt.keyID)

			if tt.expectError {
				if err == nil {
					t.Error("expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
					return
				}
				if result != tt.expectedPEM {
					t.Errorf("expected PEM %q, got %q", tt.expectedPEM, result)
				}
			}
		})
	}
}

func TestClient_SignSBOM(t *testing.T) {
	tests := []struct {
		name         string
		keyID        string
		sbom         interface{}
		mockResponse *http.Response
		mockError    error
		expectError  bool
	}{
		{
			name:  "successful SBOM signing",
			keyID: "key-123",
			sbom:  map[string]string{"name": "test-sbom"},
			mockResponse: createMockResponse(200, SignResultAPIResponse{
				"signed_sbom": map[string]interface{}{"signed": true},
				"signature":   "signature-data",
				"algorithm":   "ES256",
				"key_id":      "key-123",
			}),
			expectError: false,
		},
		{
			name:        "empty key ID",
			keyID:       "",
			sbom:        map[string]string{"name": "test-sbom"},
			expectError: true,
		},
		{
			name:        "nil SBOM",
			keyID:       "key-123",
			sbom:        nil,
			expectError: true,
		},
		{
			name:        "request failure",
			keyID:       "key-123",
			sbom:        map[string]string{"name": "test-sbom"},
			mockError:   fmt.Errorf("network error"),
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := &MockHTTPClient{
				DoFunc: func(req *http.Request) (*http.Response, error) {
					if tt.keyID != "" && tt.sbom != nil {
						expectedURL := fmt.Sprintf("https://api.example.com/v0/sbom/%s/sign?sigType=simple", tt.keyID)
						if req.URL.String() != expectedURL {
							t.Errorf("expected URL %q, got %q", expectedURL, req.URL.String())
						}

						// Verify request body contains SBOM
						if req.Body != nil {
							bodyBytes, _ := io.ReadAll(req.Body)
							var requestBody map[string]interface{}
							if json.Unmarshal(bodyBytes, &requestBody) == nil {
								if _, ok := requestBody["sbom"]; !ok {
									t.Error("expected request body to contain 'sbom' field")
								}
							}
						}
					}
					if req.Method != "POST" {
						t.Errorf("expected POST method, got %q", req.Method)
					}

					if tt.mockError != nil {
						return nil, tt.mockError
					}
					return tt.mockResponse, nil
				},
			}

			client := &Client{
				config: &Config{
					APIKey:    "test-key",
					BaseURL:   "https://api.example.com",
					UserAgent: UserAgent,
				},
				httpClient: mockClient,
			}

			ctx := context.Background()
			result, err := client.SignSBOM(ctx, tt.keyID, tt.sbom)

			if tt.expectError {
				if err == nil {
					t.Error("expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
					return
				}
				if result == nil {
					t.Error("expected result to be non-nil")
				}
			}
		})
	}
}

func TestClient_VerifySBOM(t *testing.T) {
	tests := []struct {
		name         string
		keyID        string
		signedSBOM   interface{}
		mockResponse *http.Response
		mockError    error
		expectError  bool
	}{
		{
			name:       "successful SBOM verification",
			keyID:      "key-123",
			signedSBOM: map[string]interface{}{"signed": true},
			mockResponse: createMockResponse(200, VerifyResultCMDResponse{
				Valid:     true,
				Message:   "some message",
				KeyID:     "keyid",
				Timestamp: time.Now(),
			}),
			expectError: false,
		},
		{
			name:        "empty key ID",
			keyID:       "",
			signedSBOM:  map[string]interface{}{"signed": true},
			expectError: true,
		},
		{
			name:        "nil signed SBOM",
			keyID:       "key-123",
			signedSBOM:  nil,
			expectError: true,
		},
		{
			name:        "request failure",
			keyID:       "key-123",
			signedSBOM:  map[string]interface{}{"signed": true},
			mockError:   fmt.Errorf("network error"),
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := &MockHTTPClient{
				DoFunc: func(req *http.Request) (*http.Response, error) {
					if tt.keyID != "" && tt.signedSBOM != nil {
						expectedURL := fmt.Sprintf("https://api.example.com/v0/sbom/%s/verify", tt.keyID)
						if req.URL.String() != expectedURL {
							t.Errorf("expected URL %q, got %q", expectedURL, req.URL.String())
						}

						// Verify request body contains signed SBOM
						if req.Body != nil {
							bodyBytes, _ := io.ReadAll(req.Body)
							var requestBody map[string]interface{}
							if json.Unmarshal(bodyBytes, &requestBody) == nil {
								if _, ok := requestBody["signed_sbom"]; !ok {
									t.Error("expected request body to contain 'signed_sbom' field")
								}
							}
						}
					}
					if req.Method != "POST" {
						t.Errorf("expected POST method, got %q", req.Method)
					}

					if tt.mockError != nil {
						return nil, tt.mockError
					}
					return tt.mockResponse, nil
				},
			}

			client := &Client{
				config: &Config{
					APIKey:    "test-key",
					BaseURL:   "https://api.example.com",
					UserAgent: UserAgent,
				},
				httpClient: mockClient,
			}

			ctx := context.Background()
			result, err := client.VerifySBOM(ctx, tt.keyID, tt.signedSBOM)

			if tt.expectError {
				if err == nil {
					t.Error("expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
					return
				}
				if result == nil {
					t.Error("expected result to be non-nil")
				}
			}
		})
	}
}

func TestAPIError_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      *APIError
		expected string
	}{
		{
			name: "error with details",
			err: &APIError{
				StatusCode: 400,
				Message:    "Bad Request",
				Details:    "Missing parameter",
			},
			expected: "secure-sbom API error 400: Bad Request (Missing parameter)",
		},
		{
			name: "error without details",
			err: &APIError{
				StatusCode: 404,
				Message:    "Not Found",
			},
			expected: "secure-sbom API error 404: Not Found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.err.Error()
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestAPIError_Temporary(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		expected   bool
	}{
		{name: "400 Bad Request", statusCode: 400, expected: false},
		{name: "404 Not Found", statusCode: 404, expected: false},
		{name: "429 Too Many Requests", statusCode: 429, expected: true},
		{name: "500 Internal Server Error", statusCode: 500, expected: true},
		{name: "502 Bad Gateway", statusCode: 502, expected: true},
		{name: "503 Service Unavailable", statusCode: 503, expected: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := &APIError{StatusCode: tt.statusCode}
			result := err.Temporary()
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}
