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
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"time"
)

type ConfigBuilder struct {
	config Config
}

type SBOM struct {
	data interface{}
}

type RetryConfig struct {
	MaxAttempts int
	InitialWait time.Duration
	MaxWait     time.Duration
	Multiplier  float64
}

type ClientOption func(*Config)

type RetryingClient struct {
	client      *Client
	retryConfig RetryConfig
}

func NewConfigBuilder() *ConfigBuilder {
	return &ConfigBuilder{}
}

func (b *ConfigBuilder) WithBaseURL(baseURL string) *ConfigBuilder {
	b.config.BaseURL = baseURL
	return b
}

func (b *ConfigBuilder) WithAPIKey(apiKey string) *ConfigBuilder {
	b.config.APIKey = apiKey
	return b
}

func (b *ConfigBuilder) WithTimeout(timeout time.Duration) *ConfigBuilder {
	b.config.Timeout = timeout
	return b
}

func (b *ConfigBuilder) WithHTTPClient(client HTTPClient) *ConfigBuilder {
	b.config.HTTPClient = client
	return b
}

func (b *ConfigBuilder) WithUserAgent(userAgent string) *ConfigBuilder {
	b.config.UserAgent = userAgent
	return b
}

func (b *ConfigBuilder) FromEnv() *ConfigBuilder {
	if apiKey := os.Getenv("SECURE_SBOM_API_KEY"); apiKey != "" {
		b.config.APIKey = apiKey
	}
	if baseURL := os.Getenv("SECURE_SBOM_BASE_URL"); baseURL != "" {
		b.config.BaseURL = baseURL
	} else {
		b.config.BaseURL = DEFAULT_SECURE_SBOM_BASE_URL
	}
	return b
}

func (b *ConfigBuilder) Build() *Config {
	// Return a copy to prevent external mutation
	config := b.config
	return &config
}

func (b *ConfigBuilder) BuildClient() (*Client, error) {
	return NewClient(b.Build())
}

func NewSBOM(data interface{}) *SBOM {
	return &SBOM{data: data}
}

func LoadSBOMFromReader(reader io.Reader) (*SBOM, error) {
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read data: %w", err)
	}

	if len(data) == 0 {
		return nil, fmt.Errorf("no data provided")
	}

	var sbomData interface{}
	if err := json.Unmarshal(data, &sbomData); err != nil {
		return nil, fmt.Errorf("failed to parse SBOM JSON: %w", err)
	}

	return &SBOM{data: sbomData}, nil
}

func LoadSBOMFromFile(filePath string) (*SBOM, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file %s: %w", filePath, err)
	}
	defer file.Close()

	return LoadSBOMFromReader(file)
}

func (s *SBOM) Data() interface{} {
	return s.data
}

func (s *SBOM) WriteToWriter(writer io.Writer) error {
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(s.data)
}

func (s *SBOM) WriteToFile(filePath string) error {
	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to create file %s: %w", filePath, err)
	}
	defer file.Close()

	return s.WriteToWriter(file)
}

func (s *SBOM) String() string {
	data, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return fmt.Sprintf("Error marshaling SBOM: %v", err)
	}
	return string(data)
}

func DefaultRetryConfig() RetryConfig {
	return RetryConfig{
		MaxAttempts: 3,
		InitialWait: 1 * time.Second,
		MaxWait:     10 * time.Second,
		Multiplier:  2.0,
	}
}

func WithRetry(ctx context.Context, config RetryConfig, fn func() error) error {
	var lastErr error

	for attempt := 0; attempt < config.MaxAttempts; attempt++ {
		if err := fn(); err != nil {
			lastErr = err

			// Check if error is retryable
			if apiErr, ok := err.(*APIError); ok && !apiErr.Temporary() {
				return err // Don't retry non-temporary errors
			}

			// Don't wait after the last attempt
			if attempt == config.MaxAttempts-1 {
				break
			}

			// Calculate wait time with exponential backoff
			waitTime := time.Duration(float64(config.InitialWait) *
				math.Pow(config.Multiplier, float64(attempt)))
			if waitTime > config.MaxWait {
				waitTime = config.MaxWait
			}

			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(waitTime):
				// Continue to next attempt
			}
		} else {
			return nil // Success
		}
	}

	return fmt.Errorf("operation failed after %d attempts: %w", config.MaxAttempts, lastErr)
}

func WithRetryingClient(client *Client, retryConfig RetryConfig) *RetryingClient {
	return &RetryingClient{
		client:      client,
		retryConfig: retryConfig,
	}
}

func (r *RetryingClient) HealthCheck(ctx context.Context) error {
	return WithRetry(ctx, r.retryConfig, func() error {
		return r.client.HealthCheck(ctx)
	})
}

func (r *RetryingClient) ListKeys(ctx context.Context) (*KeyListResponse, error) {
	var result *KeyListResponse
	err := WithRetry(ctx, r.retryConfig, func() error {
		var err error
		result, err = r.client.ListKeys(ctx)
		return err
	})
	return result, err
}

func (r *RetryingClient) GenerateKey(ctx context.Context) (*GenerateKeyCMDResponse, error) {
	var result *GenerateKeyCMDResponse
	err := WithRetry(ctx, r.retryConfig, func() error {
		var err error
		result, err = r.client.GenerateKey(ctx)
		return err
	})
	return result, err
}

func (r *RetryingClient) GetPublicKey(ctx context.Context, keyID string) (string, error) {
	var result string
	err := WithRetry(ctx, r.retryConfig, func() error {
		var err error
		result, err = r.client.GetPublicKey(ctx, keyID)
		return err
	})
	return result, err
}

func (r *RetryingClient) SignSBOM(ctx context.Context, keyID string, sbom interface{}) (*SignResultAPIResponse, error) {
	var result *SignResultAPIResponse
	err := WithRetry(ctx, r.retryConfig, func() error {
		var err error
		result, err = r.client.SignSBOM(ctx, keyID, sbom)
		return err
	})
	return result, err
}

func (r *RetryingClient) VerifySBOM(ctx context.Context, keyID string, signedSBOM interface{}) (*VerifyResultCMDResponse, error) {
	var result *VerifyResultCMDResponse
	err := WithRetry(ctx, r.retryConfig, func() error {
		var err error
		result, err = r.client.VerifySBOM(ctx, keyID, signedSBOM)
		return err
	})
	return result, err
}
