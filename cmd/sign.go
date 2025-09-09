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
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/interlynk-io/sbomasm/pkg/securesbom"
	"github.com/spf13/cobra"
)

// signCmd represents the sign command
var signCmd = &cobra.Command{
	Use:   "sign",
	Short: "Sign an SBOM using ShiftLeftCyber's SecureSBOM API",
	Long: `Sign an SBOM using a cryptographic key from the ShiftLeftCyber's SecureSBOM API service. Utilizez the CycloneDX Signature Specification or a detached signature for SPDX types.

This service requires an API key to access ShiftLeftCybers's SecureSBOM API. To obtain an API
Key use the following link: https://shiftleftcyber.io/contactus

The sign command takes an SBOM file, sends it to the Secure SBOM API for signing.
The output is the signed SBOM. The signing process adds cryptographic proof of
authenticity and integrity to the SBOM.

Examples:
  # Sign an SBOM with a specific key
  sbomasm sign --key-id my-key-123 --api-key $API_KEY sbom.json

  # Sign with environment variable for API key
  export SECURE_SBOM_API_KEY=your-api-key
  sbomasm sign --key-id my-key-123 --output signed-sbom.json sbom.json

  # Sign with custom API endpoint
  sbomasm sign --key-id my-key-123 --base-url https://custom.api.com sbom.json`,
	Args:         cobra.ExactArgs(1),
	SilenceUsage: true,
	PreRunE:      validateSignFlags,
	RunE:         runSignCommand,
}

// Sign command flags
var (
	signKeyID      string
	signAPIKey     string
	signBaseURL    string
	signOutput     string
	signTimeout    time.Duration
	signRetryCount int
	signQuiet      bool
)

func init() {
	rootCmd.AddCommand(signCmd)

	// Required flags
	signCmd.Flags().StringVar(&signKeyID, "key-id", "", "Key ID to use for signing")

	// Authentication flags
	signCmd.Flags().StringVar(&signAPIKey, "api-key", "", "API key for authentication (or set SECURE_SBOM_API_KEY)")
	signCmd.Flags().StringVar(&signBaseURL, "base-url", "", "Base URL for Secure SBOM API (or set SECURE_SBOM_BASE_URL)")

	// Output flags
	signCmd.Flags().StringVar(&signOutput, "output", "", "Output file path (use '-' for stdout, default: stdout)")
	signCmd.Flags().BoolVar(&signQuiet, "quiet", false, "Suppress progress output")

	// Advanced flags
	signCmd.Flags().DurationVar(&signTimeout, "timeout", 30*time.Second, "Request timeout")
	signCmd.Flags().IntVar(&signRetryCount, "retry", 3, "Number of retry attempts for failed requests")

	// Mark required flags
	signCmd.MarkFlagRequired("key-id")
}

func validateSignFlags(cmd *cobra.Command, args []string) error {
	// Validate input file argument
	if len(args) == 0 {
		return fmt.Errorf("input file is required")
	}

	// Check if input file exists (unless it's stdin)
	if args[0] != "-" {
		if _, err := os.Stat(args[0]); err != nil {
			return fmt.Errorf("invalid input file: %v", err)
		}
	}

	// Validate key ID
	if signKeyID == "" {
		return fmt.Errorf("--key-id is required")
	}

	// Check for API key in flag or environment
	if signAPIKey == "" {
		signAPIKey = os.Getenv("SECURE_SBOM_API_KEY")
		if signAPIKey == "" {
			return fmt.Errorf("API key is required. Use --api-key flag or set SECURE_SBOM_API_KEY environment variable")
		}
	}

	// Validate timeout
	if signTimeout <= 0 {
		return fmt.Errorf("--timeout must be positive")
	}

	// Validate retry count
	if signRetryCount < 0 {
		return fmt.Errorf("--retry cannot be negative")
	}

	return nil
}

func runSignCommand(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), signTimeout+10*time.Second)
	defer cancel()

	// Create SDK client
	client, err := createSignClient()
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}

	// Load SBOM
	if !signQuiet {
		fmt.Fprintf(os.Stderr, "Loading SBOM...\n")
	}

	sbom, err := loadSBOMForSigning(args[0])
	if err != nil {
		return fmt.Errorf("failed to load SBOM: %w", err)
	}

	// Perform health check
	if !signQuiet {
		fmt.Fprintf(os.Stderr, "Connecting to Secure SBOM API...\n")
	}

	if err := client.HealthCheck(ctx); err != nil {
		return fmt.Errorf("API health check failed: %w", err)
	}

	// Sign the SBOM
	if !signQuiet {
		fmt.Fprintf(os.Stderr, "Signing SBOM with key %s...\n", signKeyID)
	}

	result, err := client.SignSBOM(ctx, signKeyID, sbom.Data())
	if err != nil {
		return fmt.Errorf("failed to sign SBOM: %w", err)
	}

	// Output the signed SBOM (with pretty formatting)
	if err := outputSignedSBOM(result); err != nil {
		return fmt.Errorf("failed to output signed SBOM: %w", err)
	}

	// Success message and metadata
	if !signQuiet {
		fmt.Fprintf(os.Stderr, "\n\nSBOM successfully signed\n")

		if signature := result.GetSignatureValue(); signature != "" {
			fmt.Fprintf(os.Stderr, "  Signature: %s\n", truncateString(signature, 50))
		}

		if algorithm := result.GetSignatureAlgorithm(); algorithm != "" {
			fmt.Fprintf(os.Stderr, "  Algorithm: %s\n", algorithm)
		}

		// Show where output was written
		if signOutput != "" {
			fmt.Fprintf(os.Stderr, "  Output: %s\n", signOutput)
		} else {
			fmt.Fprintf(os.Stderr, "  Output: stdout\n")
		}
	}

	return nil
}

func createSignClient() (securesbom.ClientInterface, error) {
	// Build configuration
	config := securesbom.NewConfigBuilder().
		WithAPIKey(signAPIKey).
		WithTimeout(signTimeout).
		FromEnv()

	if signBaseURL != "" {
		config = config.WithBaseURL(signBaseURL)
	}

	baseClient, err := config.BuildClient()
	if err != nil {
		return nil, err
	}

	// Wrap with retry logic if requested
	if signRetryCount > 0 {
		retryConfig := securesbom.RetryConfig{
			MaxAttempts: signRetryCount,
			InitialWait: 1 * time.Second,
			MaxWait:     10 * time.Second,
			Multiplier:  2.0,
		}
		return securesbom.WithRetryingClient(baseClient, retryConfig), nil
	}

	return baseClient, nil
}

func loadSBOMForSigning(inputFile string) (*securesbom.SBOM, error) {
	if inputFile == "-" {
		return securesbom.LoadSBOMFromReader(os.Stdin)
	}

	return securesbom.LoadSBOMFromFile(inputFile)
}

// outputSignedSBOM writes the signed SBOM to the specified output location with pretty formatting
func outputSignedSBOM(result *securesbom.SignResultAPIResponse) error {
	// Pretty-print the JSON with indentation
	prettyJSON, err := json.MarshalIndent(*result, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to format signed SBOM as JSON: %w", err)
	}

	// If no output file specified, write to stdout
	if signOutput == "" {
		_, err := os.Stdout.Write(prettyJSON)
		if err != nil {
			return fmt.Errorf("failed to write to stdout: %w", err)
		}
		// Add a newline at the end for better terminal output
		fmt.Println()
		return nil
	}

	// Create output directory if it doesn't exist
	if err := os.MkdirAll(filepath.Dir(signOutput), 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Write to file with proper permissions
	if err := os.WriteFile(signOutput, prettyJSON, 0644); err != nil {
		return fmt.Errorf("failed to write signed SBOM to file %s: %w", signOutput, err)
	}

	return nil
}

// truncateString truncates a string to maxLen characters with ellipsis
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return "..."
	}
	return s[:maxLen-3] + "..."
}
