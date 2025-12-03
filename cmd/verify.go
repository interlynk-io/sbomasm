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
	"time"

	"github.com/shiftleftcyber/securesbom-sdk-golang/v2/pkg/securesbom"
	"github.com/spf13/cobra"
)

// verifyCmd represents the verify command
var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verifies a signed SBOM using ShiftLeftCyber's SecureSBOM API",
	Long: `Verify the authenticity and integrity of a signed SBOM document.

This service requires an API key to access ShiftLeftCybers's SecureSBOM solution. To obtain an API
Key use the following link: https://shiftleftcyber.io/contactus

The verify command takes a signed SBOM file, sends it to the SecureSBOM API
for verification, and reports whether the signature is cryptographically valid. This ensures
the SBOM hasn't been tampered with since it was signed.

Examples:
  # Verify a signed CycloneDX SBOM
  sbomasm verify --key-id a7b3c9e1-2f4d-4a8b-9c6e-1d5f7a9b2c4e --api-key $API_KEY signed-cyclonedx-sbom.json

  # Verify a SPDX Detached Signature
  sbomasm verify --key-id a7b3c9e1-2f4d-4a8b-9c6e-1d5f7a9b2c4e --signature "SIGNATURE HASH" --api-key $API_KEY signed-cyclonedx-sbom.json

  # Verify with environment variable for API key
  export SECURE_SBOM_API_KEY=your-api-key
  sbomasm verify --key-id a7b3c9e1-2f4d-4a8b-9c6e-1d5f7a9b2c4e signed-sbom.json

  # Verify with custom API endpoint
  sbomasm verify --key-id a7b3c9e1-2f4d-4a8b-9c6e-1d5f7a9b2c4e --base-url https://custom.api.com signed-sbom.json

  # Verify with JSON output for automation
  sbomasm verify --key-id a7b3c9e1-2f4d-4a8b-9c6e-1d5f7a9b2c4e --output json signed-sbom.json`,
	Args:         cobra.ExactArgs(1),
	SilenceUsage: true,
	PreRunE:      validateVerifyFlags,
	RunE:         runVerifyCommand,
}

// Verify command flags
var (
	verifyKeyID        string
	verifyAPIKey       string
	verifyBaseURL      string
	verifyOutputFormat string
	verifyTimeout      time.Duration
	verifyRetryCount   int
	verifyQuiet        bool
	verifySignature	   string
)

// VerificationOutput represents the CLI output structure
type VerificationOutput struct {
	Status    string    `json:"status"`
	Valid     bool      `json:"valid"`
	Message   string    `json:"message,omitempty"`
	KeyID     string    `json:"key_id,omitempty"`
	Algorithm string    `json:"algorithm,omitempty"`
	Timestamp time.Time `json:"timestamp,omitempty"`
}

func init() {
	// Add verify command to root
	rootCmd.AddCommand(verifyCmd)

	// Verification Flag
	verifyCmd.Flags().StringVar(&verifyKeyID, "key-id", "", "Key ID used to sign the SBOM")
	verifyCmd.Flags().StringVar(&verifySignature, "signature", "", "Base64 signature to veirfy when using an SPDX SBOM")

	// Authentication flags
	verifyCmd.Flags().StringVar(&verifyAPIKey, "api-key", "", "API key for authentication (or set SECURE_SBOM_API_KEY)")
	verifyCmd.Flags().StringVar(&verifyBaseURL, "base-url", "", "Base URL for Secure SBOM API (or set SECURE_SBOM_BASE_URL)")

	// Output flags
	verifyCmd.Flags().StringVar(&verifyOutputFormat, "output", "text", "Output format: text, json")
	verifyCmd.Flags().BoolVar(&verifyQuiet, "quiet", false, "Suppress progress output (only show result)")

	// Advanced flags
	verifyCmd.Flags().DurationVar(&verifyTimeout, "timeout", 30*time.Second, "Request timeout")
	verifyCmd.Flags().IntVar(&verifyRetryCount, "retry", 3, "Number of retry attempts for failed requests")

	// Mark required flags
	verifyCmd.MarkFlagRequired("key-id")

	// Set up flag dependencies and validation
	verifyCmd.PreRunE = validateVerifyFlags
}

func validateVerifyFlags(cmd *cobra.Command, args []string) error {
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
	if verifyKeyID == "" {
		return fmt.Errorf("--key-id is required")
	}

	// Check for API key in flag or environment
	if verifyAPIKey == "" {
		verifyAPIKey = os.Getenv("SECURE_SBOM_API_KEY")
		if verifyAPIKey == "" {
			return fmt.Errorf("API key is required. Use --api-key flag or set SECURE_SBOM_API_KEY environment variable")
		}
	}

	// Validate output format
	if verifyOutputFormat != "text" && verifyOutputFormat != "json" {
		return fmt.Errorf("--output must be 'text' or 'json'")
	}

	// Validate timeout
	if verifyTimeout <= 0 {
		return fmt.Errorf("--timeout must be positive")
	}

	// Validate retry count
	if verifyRetryCount < 0 {
		return fmt.Errorf("--retry cannot be negative")
	}

	// Detect SBOM format and validate signature requirement
	if args[0] != "-" {
		format, err := detectSBOMFormat(args[0])
		if err != nil {
			// If we can't detect the format, we'll let the SDK handle it later
			// This allows the verification to proceed and fail with a more specific error
			return nil
		}

		if format == "spdx" && verifySignature == "" {
			return fmt.Errorf("--signature is required for SPDX SBOMs")
		}
	}

	return nil
}

func runVerifyCommand(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), verifyTimeout+10*time.Second)
	defer cancel()

	// Create SDK client using the same interface as signing
	client, err := createVerifyClient()
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}

	// Load signed SBOM
	if !verifyQuiet {
		fmt.Fprintf(os.Stderr, "Loading signed SBOM...\n")
	}

	signedSBOM, err := loadSBOMForVerification(args[0])
	if err != nil {
		return fmt.Errorf("failed to load signed SBOM: %w", err)
	}

	// Perform health check
	if !verifyQuiet {
		fmt.Fprintf(os.Stderr, "Connecting to Secure SBOM API...\n")
	}

	if err := client.HealthCheck(ctx); err != nil {
		return fmt.Errorf("API health check failed: %w", err)
	}

	var result *securesbom.VerifyResultCMDResponse
	if verifySignature != "" {
		// SPDX SBOM - use separate signature
		if !verifyQuiet {
			fmt.Fprintf(os.Stderr, "Verifying SPDX SBOM with provided signature...\n")
		}
		result, err = client.VerifySPDXSBOM(ctx, verifyKeyID, verifySignature, signedSBOM.Data())
		if err != nil {
			return fmt.Errorf("failed to verify SPDX SBOM: %w", err)
		}
	} else {
		// CycloneDX SBOM - signature embedded in SBOM
		if !verifyQuiet {
			fmt.Fprintf(os.Stderr, "Verifying CycloneDX SBOM with embedded signature...\n")
		}
		result, err = client.VerifySBOM(ctx, verifyKeyID, signedSBOM.Data())
		if err != nil {
			return fmt.Errorf("failed to verify CycloneDX SBOM: %w", err)
		}
	}

	// Output the verification result
	if err := outputVerificationResult(result); err != nil {
		return fmt.Errorf("failed to output verification result: %w", err)
	}

	// Set exit code based on verification result
	if !result.Valid {
		os.Exit(1)
	}

	return nil
}

// Updated createVerifyClient to use the same interface as signing
func createVerifyClient() (securesbom.ClientInterface, error) {
	// Build configuration
	config := securesbom.NewConfigBuilder().
		WithAPIKey(verifyAPIKey).
		WithTimeout(verifyTimeout).
		FromEnv()

	if verifyBaseURL != "" {
		config = config.WithBaseURL(verifyBaseURL)
	}

	baseClient, err := config.BuildClient()
	if err != nil {
		return nil, err
	}

	// Wrap with retry logic if requested
	if verifyRetryCount > 0 {
		retryConfig := securesbom.RetryConfig{
			MaxAttempts: verifyRetryCount,
			InitialWait: 1 * time.Second,
			MaxWait:     10 * time.Second,
			Multiplier:  2.0,
		}
		return securesbom.WithRetryingClient(baseClient, retryConfig), nil
	}

	return baseClient, nil
}

func loadSBOMForVerification(inputFile string) (*securesbom.SBOM, error) {
	if inputFile == "-" {
		return securesbom.LoadSBOMFromReader(os.Stdin)
	}

	return securesbom.LoadSBOMFromFile(inputFile)
}

func outputVerificationResult(result *securesbom.VerifyResultCMDResponse) error {
	output := VerificationOutput{
		Valid:     result.Valid,
		Message:   result.Message,
		KeyID:     result.KeyID,
		Algorithm: result.Algorithm,
		Timestamp: result.Timestamp,
	}

	if result.Valid {
		output.Status = "VALID"
	} else {
		output.Status = "INVALID"
	}

	switch verifyOutputFormat {
	case "json":
		return outputVerificationJSON(output)
	case "text":
		return outputVerificationText(output)
	default:
		return fmt.Errorf("unsupported output format: %s", verifyOutputFormat)
	}
}

func outputVerificationJSON(output VerificationOutput) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(output)
}

func outputVerificationText(output VerificationOutput) error {
	if output.Valid {
		fmt.Printf("✓ SBOM signature is VALID\n")
	} else {
		fmt.Printf("✗ SBOM signature is INVALID\n")
	}

	if output.Message != "" {
		fmt.Printf("Message: %s\n", output.Message)
	}

	if output.KeyID != "" {
		fmt.Printf("Key ID: %s\n", output.KeyID)
	}

	if output.Algorithm != "" {
		fmt.Printf("Algorithm: %s\n", output.Algorithm)
	}

	if !output.Timestamp.IsZero() {
		fmt.Printf("Verified at: %s\n", output.Timestamp.Format(time.RFC3339))
	}

	return nil
}

// detectSBOMFormat attempts to detect if the SBOM is SPDX or CycloneDX
func detectSBOMFormat(filepath string) (string, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	var peek map[string]interface{}
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&peek); err != nil {
		return "", err
	}

	// SPDX SBOMs have "spdxVersion" field
	if _, hasSPDXVersion := peek["spdxVersion"]; hasSPDXVersion {
		return "spdx", nil
	}

	// CycloneDX SBOMs have "bomFormat" field
	if bomFormat, hasBomFormat := peek["bomFormat"]; hasBomFormat {
		if fmt.Sprintf("%v", bomFormat) == "CycloneDX" {
			return "cyclonedx", nil
		}
	}

	return "", fmt.Errorf("unable to detect SBOM format")
}
