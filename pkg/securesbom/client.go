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

// Package securesbom provides a Go SDK for interacting with the SecureSBOM API by ShiftLeftCyber.
//
// This SDK is designed to be framework-agnostic and can be used in CLI tools,
// web applications, or any other Go application that needs to cryptographically sign and verify SBOMs.
//
// Basic usage:
//
//	client := securesbom.NewClient(&securesbom.Config{
//		BaseURL: "https://your-api.googleapis.com",
//		APIKey:  "your-api-key",
//	})
//
//	// Sign an SBOM
//	result, err := client.SignSBOM(ctx, "key-id", sbomData)
//
//	// Verify an SBOM
//	result, err := client.VerifySBOM(ctx, "key-id", signedSBOM)

package securesbom

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	DefaultTimeout = 30 * time.Second
	UserAgent      = "secure-sbom-sdk-go/1.0"
)

type Client struct {
	config     *Config
	httpClient HTTPClient
}

type ClientInterface interface {
	HealthCheck(ctx context.Context) error
	ListKeys(ctx context.Context) (*KeyListResponse, error)
	GenerateKey(ctx context.Context) (*GenerateKeyCMDResponse, error)
	GetPublicKey(ctx context.Context, keyID string) (string, error)
	SignSBOM(ctx context.Context, keyID string, sbom interface{}) (*SignResultAPIResponse, error)
	VerifySBOM(ctx context.Context, keyID string, signedSBOM interface{}) (*VerifyResultCMDResponse, error)
}

func (e *APIError) Error() string {
	if e.Details != "" {
		return fmt.Sprintf("secure-sbom API error %d: %s (%s)", e.StatusCode, e.Message, e.Details)
	}
	return fmt.Sprintf("secure-sbom API error %d: %s", e.StatusCode, e.Message)
}

// Temporary returns true if the error is likely temporary and retryable
func (e *APIError) Temporary() bool {
	return e.StatusCode >= 500 || e.StatusCode == 429
}

func NewClient(config *Config) (*Client, error) {
	if config == nil {
		return nil, fmt.Errorf("config is required")
	}

	if err := validateConfig(config); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	cfg := *config

	if cfg.Timeout == 0 {
		cfg.Timeout = DefaultTimeout
	}
	if cfg.UserAgent == "" {
		cfg.UserAgent = UserAgent
	}

	var httpClient HTTPClient = cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{
			Timeout: cfg.Timeout,
		}
	}

	return &Client{
		config:     &cfg,
		httpClient: httpClient,
	}, nil
}

func validateConfig(config *Config) error {
	if config.APIKey == "" {
		return fmt.Errorf("APIKey is required")
	}

	if config.BaseURL == "" {
		return fmt.Errorf("BaseURL is required")
	}

	if _, err := url.Parse(config.BaseURL); err != nil {
		return fmt.Errorf("invalid BaseURL: %w", err)
	}

	if config.Timeout < 0 {
		return fmt.Errorf("Timeout cannot be negative")
	}

	return nil
}

func (c *Client) buildURL(endpoint string) string {
	baseURL := strings.TrimSuffix(c.config.BaseURL, "/")
	endpoint = strings.TrimPrefix(endpoint, "/")
	return fmt.Sprintf("%s/%s", baseURL, endpoint)
}

func (c *Client) doRequest(ctx context.Context, method, endpoint string, body interface{}) (*http.Response, error) {
	url := c.buildURL(endpoint)

	var bodyReader io.Reader
	if body != nil {
		bodyBytes, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
		bodyReader = bytes.NewReader(bodyBytes)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set authentication and headers
	req.Header.Set("x-api-key", c.config.APIKey)
	req.Header.Set("User-Agent", c.config.UserAgent)
	req.Header.Set("Accept", "application/json")

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}

	// Handle HTTP error status codes
	if resp.StatusCode >= 400 {
		defer resp.Body.Close()

		apiErr := &APIError{
			StatusCode: resp.StatusCode,
			Message:    http.StatusText(resp.StatusCode),
		}

		// Try to parse structured error response
		if bodyBytes, err := io.ReadAll(resp.Body); err == nil && len(bodyBytes) > 0 {
			var errorResp struct {
				Message   string `json:"message"`
				Details   string `json:"details"`
				RequestID string `json:"request_id"`
				Error     string `json:"error"` // Alternative field name
			}

			if json.Unmarshal(bodyBytes, &errorResp) == nil {
				if errorResp.Message != "" {
					apiErr.Message = errorResp.Message
				} else if errorResp.Error != "" {
					apiErr.Message = errorResp.Error
				}
				apiErr.Details = errorResp.Details
				apiErr.RequestID = errorResp.RequestID
			}
		}

		return nil, apiErr
	}

	return resp, nil
}

func (c *Client) doMultipartRequest(ctx context.Context, method, endpoint string, body io.Reader, contentType string) (*http.Response, error) {
	url := c.buildURL(endpoint)

	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set authentication and headers
	req.Header.Set("x-api-key", c.config.APIKey)
	req.Header.Set("User-Agent", c.config.UserAgent)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", contentType)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}

	if resp.StatusCode >= 400 {
		defer resp.Body.Close()

		apiErr := &APIError{
			StatusCode: resp.StatusCode,
			Message:    http.StatusText(resp.StatusCode),
		}

		if bodyBytes, err := io.ReadAll(resp.Body); err == nil && len(bodyBytes) > 0 {
			var errorResp struct {
				Message   string `json:"message"`
				Details   string `json:"details"`
				RequestID string `json:"request_id"`
				Error     string `json:"error"`
			}

			if json.Unmarshal(bodyBytes, &errorResp) == nil {
				if errorResp.Message != "" {
					apiErr.Message = errorResp.Message
				} else if errorResp.Error != "" {
					apiErr.Message = errorResp.Error
				}
				apiErr.Details = errorResp.Details
				apiErr.RequestID = errorResp.RequestID
			}
		}

		return nil, apiErr
	}

	return resp, nil
}

func (c *Client) HealthCheck(ctx context.Context) error {
	resp, err := c.doRequest(ctx, "GET", API_ENDPOINT_HEALTHCHECK, nil)
	if err != nil {
		return fmt.Errorf("health check failed: %w", err)
	}
	defer resp.Body.Close()

	return nil
}

func (c *Client) ListKeys(ctx context.Context) (*KeyListResponse, error) {
	resp, err := c.doRequest(ctx, "GET", API_VERSION + API_ENDPOINT_KEYS + "?showpub=false", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to list keys: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(body))
	}

	// Parse as array of API key items
	var apiKeys []ListKeysAPIResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiKeys); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	// Convert to GeneratedKey
	keys := make([]GenerateKeyCMDResponse, len(apiKeys))
	for i, apiKey := range apiKeys {
		keys[i] = GenerateKeyCMDResponse{
			ID:        apiKey.ID,
			CreatedAt: apiKey.CreatedAt,
			Algorithm: apiKey.Algorithm,
		}
	}

	return &KeyListResponse{Keys: keys}, nil
}

func (c *Client) GenerateKey(ctx context.Context) (*GenerateKeyCMDResponse, error) {
	resp, err := c.doRequest(ctx, HTTP_METHOD_POST, API_VERSION + API_ENDPOINT_KEYS + "?alg=ES256", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(body))
	}

	var apiResp GenerateKeyAPIReponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &GenerateKeyCMDResponse{
		ID:        apiResp.KeyID,
		PublicKey: apiResp.PublicKey,
		CreatedAt: time.Now(),
		Algorithm: "ES256",
	}, nil
}

// GetPublicKey retrieves the public key for a specific key ID
func (c *Client) GetPublicKey(ctx context.Context, keyID string) (string, error) {
	if keyID == "" {
		return "", fmt.Errorf("keyID is required")
	}

	endpoint := fmt.Sprintf(API_VERSION + API_ENDPOINT_KEYS + "/%s/public.pem", keyID)
	resp, err := c.doRequest(ctx, "GET", endpoint, nil)
	if err != nil {
		return "", fmt.Errorf("failed to get public key: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(body))
	}

	// Read the PEM content as plain text
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %w", err)
	}

	return string(body), nil
}

func (c *Client) SignSBOM(ctx context.Context, keyID string, sbom interface{}) (*SignResultAPIResponse, error) {
	if keyID == "" {
		return nil, fmt.Errorf("keyID is required")
	}
	if sbom == nil {
		return nil, fmt.Errorf("sbom is required")
	}

	endpoint := fmt.Sprintf(API_VERSION + API_ENDPOINT_SBOM + "/%s/sign?sigType=simple", keyID)

	sbomBytes, err := json.Marshal(sbom)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal SBOM: %w", err)
	}

	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)

	part, err := writer.CreateFormFile("sbom", "sbom.json")
	if err != nil {
		return nil, fmt.Errorf("failed to create form file: %w", err)
	}

	if _, err := part.Write(sbomBytes); err != nil {
		return nil, fmt.Errorf("failed to write SBOM data: %w", err)
	}

	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("failed to close form writer: %w", err)
	}

	resp, err := c.doMultipartRequest(ctx, "POST", endpoint, &buf, writer.FormDataContentType())
	if err != nil {
		return nil, fmt.Errorf("failed to sign SBOM: %w", err)
	}
	defer resp.Body.Close()

	var result SignResultAPIResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &result, nil
}

// VerifySBOM verifies a signed SBOM using the specified key
func (c *Client) VerifySBOM(ctx context.Context, keyID string, signedSBOM interface{}) (*VerifyResultCMDResponse, error) {
	if keyID == "" {
		return nil, fmt.Errorf("keyID is required")
	}
	if signedSBOM == nil {
		return nil, fmt.Errorf("signedSBOM is required")
	}

	endpoint := fmt.Sprintf(API_VERSION + API_ENDPOINT_SBOM + "/%s/verify", keyID)

	signedSBOMBytes, err := json.Marshal(signedSBOM)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal signed SBOM: %w", err)
	}

	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)

	part, err := writer.CreateFormFile("signedSBOM", "signed-sbom.json")
	if err != nil {
		return nil, fmt.Errorf("failed to create form file: %w", err)
	}

	if _, err := part.Write(signedSBOMBytes); err != nil {
		return nil, fmt.Errorf("failed to write signed SBOM data: %w", err)
	}

	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("failed to close form writer: %w", err)
	}

	resp, err := c.doMultipartRequest(ctx, "POST", endpoint, &buf, writer.FormDataContentType())
	if err != nil {
		return nil, fmt.Errorf("failed to verify SBOM: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	switch resp.StatusCode {
	case 200:
		// Success case - signature is valid
		var apiResp VerifyResultAPIResponse
		if err := json.Unmarshal(bodyBytes, &apiResp); err != nil {
			return nil, fmt.Errorf("failed to decode success response: %w", err)
		}

		return &VerifyResultCMDResponse{
			Valid:     true,
			Message:   apiResp.Message,
			KeyID:     apiResp.KeyID,
			Algorithm: apiResp.Algorithm,
			Timestamp: time.Now(),
		}, nil

	case 500:
		// Error case - signature verification failed
		// First try to parse as structured error response
		var apiErr APIErrorResponse
		if err := json.Unmarshal(bodyBytes, &apiErr); err != nil {
			// If JSON parsing fails, treat the response as plain text
			errorMsg := strings.TrimSpace(string(bodyBytes))
			if errorMsg == "" {
				errorMsg = "signature verification failed"
			}
			return &VerifyResultCMDResponse{
				Valid:     false,
				Message:   errorMsg,
				Timestamp: time.Now(),
			}, nil
		}

		errorMessage := apiErr.Message
		if errorMessage == "" {
			errorMessage = apiErr.Error
		}
		if errorMessage == "" {
			errorMessage = "signature verification failed"
		}

		return &VerifyResultCMDResponse{
			Valid:     false,
			Message:   errorMessage,
			Timestamp: time.Now(),
		}, nil

	default:
		return nil, fmt.Errorf("unexpected response status %d: %s", resp.StatusCode, string(bodyBytes))
	}
}
