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
	"text/tabwriter"
	"time"

	"github.com/interlynk-io/sbomasm/pkg/securesbom"
	"github.com/spf13/cobra"
)

// keyCmd represents the key management command group
var keyCmd = &cobra.Command{
	Use:   "securesbomkey",
	Short: "Manage cryptographic keys in ShiftLeftCyber's SecureSBOM API service",
	Long: `Manage cryptographic keys used for signing and verifying SBOMs.

This service requires an API key to access ShiftLeftCybers's SecureSBOM solution. To obtain an API
Key use the following link: https://shiftleftcyber.io/contactus

This command provides subcommands for listing existing keys, generating new keys,
and retrieving public keys from the Secure SBOM service.

Available subcommands:
  list      - List all available keys
  generate  - Generate a new signing key
  public    - Get the public key for a specific key ID`,
}

// keyListCmd represents the key list command
var keyListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all available signing keys",
	Long: `List all cryptographic keys available in your Secure SBOM account.

This command retrieves and displays all keys that can be used for signing SBOMs,
including their IDs, creation dates, and algorithms.

Examples:
  # List keys in table format
  sbomasm signingkey list --api-key $API_KEY

  # List keys in JSON format
  sbomasm signingkey list --output json

  # List keys with custom API endpoint
  sbomasm signingkey list --base-url https://custom.api.com`,
	RunE: runKeyListCommand,
}

// keyGenerateCmd represents the key generate command
var keyGenerateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate a new signing key",
	Long: `Generate a new cryptographic key for signing SBOMs.

This command creates a new key in your Secure SBOM account that can be used
for signing SBOMs. The key will be securely stored in the service and can
be referenced by its ID for signing operations.

Examples:
  # Generate a new key
  sbomasm signingkey generate --api-key $API_KEY

  # Generate a key and save details to file
  sbomasm signingkey generate --output key-details.json`,
	RunE: runKeyGenerateCommand,
}

// keyPublicCmd represents the key public command
var keyPublicCmd = &cobra.Command{
	Use:   "public <key-id>",
	Short: "Get the public key for a specific key ID",
	Long: `Retrieve the public key in PEM format for a specific key ID.

This command fetches the public key portion of a signing key, which can be
used for verification purposes or distributed to others who need to verify
SBOMs signed with the corresponding private key.

Examples:
  # Get public key
  sbomasm signingkey public a7b3c9e1-2f4d-4a8b-9c6e-1d5f7a9b2c4e --api-key $API_KEY

  # Save public key to file
  sbomasm signingkey public a7b3c9e1-2f4d-4a8b-9c6e-1d5f7a9b2c4e --output public.pem`,
	Args: cobra.ExactArgs(1),
	RunE: runKeyPublicCommand,
}

// Key command flags
var (
	keyAPIKey       string
	keyBaseURL      string
	keyOutputFormat string
	keyOutput       string
	keyTimeout      time.Duration
	keyRetryCount   int
	keyQuiet        bool
)

func init() {
	// Add key command to root
	rootCmd.AddCommand(keyCmd)

	// Add subcommands
	keyCmd.AddCommand(keyListCmd)
	keyCmd.AddCommand(keyGenerateCmd)
	keyCmd.AddCommand(keyPublicCmd)

	// Persistent flags for all key subcommands
	keyCmd.PersistentFlags().StringVar(&keyAPIKey, "api-key", "", "API key for authentication (or set SECURE_SBOM_API_KEY)")
	keyCmd.PersistentFlags().StringVar(&keyBaseURL, "base-url", "", "Base URL for Secure SBOM API (or set SECURE_SBOM_BASE_URL)")
	keyCmd.PersistentFlags().DurationVar(&keyTimeout, "timeout", 30*time.Second, "Request timeout")
	keyCmd.PersistentFlags().IntVar(&keyRetryCount, "retry", 3, "Number of retry attempts for failed requests")
	keyCmd.PersistentFlags().BoolVar(&keyQuiet, "quiet", false, "Suppress progress output")

	// Output flags for list and generate commands
	keyListCmd.Flags().StringVar(&keyOutputFormat, "output", "table", "Output format: table, json")
	keyGenerateCmd.Flags().StringVar(&keyOutputFormat, "output", "table", "Output format: table, json")

	// Output file flag for public command
	keyPublicCmd.Flags().StringVar(&keyOutput, "output", "", "Output file path (default: stdout)")

	// Set up validation
	keyCmd.PersistentPreRunE = validateKeyFlags
}

func validateKeyFlags(cmd *cobra.Command, args []string) error {
	// Check for API key in flag or environment
	if keyAPIKey == "" {
		keyAPIKey = os.Getenv("SECURE_SBOM_API_KEY")
		if keyAPIKey == "" {
			return fmt.Errorf("API key is required. Use --api-key flag or set SECURE_SBOM_API_KEY environment variable")
		}
	}

	// Validate timeout
	if keyTimeout <= 0 {
		return fmt.Errorf("--timeout must be positive")
	}

	// Validate retry count
	if keyRetryCount < 0 {
		return fmt.Errorf("--retry cannot be negative")
	}

	return nil
}

func runKeyListCommand(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), keyTimeout+10*time.Second)
	defer cancel()

	// Validate output format
	if keyOutputFormat != "table" && keyOutputFormat != "json" {
		return fmt.Errorf("--output must be 'table' or 'json'")
	}

	// Create SDK client
	client, err := createKeyClient()
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}

	// Perform health check
	if !keyQuiet {
		fmt.Fprintf(os.Stderr, "Connecting to Secure SBOM API...\n")
	}

	if err := client.HealthCheck(ctx); err != nil {
		return fmt.Errorf("API health check failed: %w", err)
	}

	// List keys
	if !keyQuiet {
		fmt.Fprintf(os.Stderr, "Retrieving keys...\n")
	}

	result, err := client.ListKeys(ctx)
	if err != nil {
		return fmt.Errorf("failed to list keys: %w", err)
	}

	// Output results
	switch keyOutputFormat {
	case "json":
		return outputKeysJSON(result)
	case "table":
		return outputKeysTable(result)
	default:
		return fmt.Errorf("unsupported output format: %s", keyOutputFormat)
	}
}

func runKeyGenerateCommand(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), keyTimeout+10*time.Second)
	defer cancel()

	// Validate output format
	if keyOutputFormat != "table" && keyOutputFormat != "json" {
		return fmt.Errorf("--output must be 'table' or 'json'")
	}

	// Create SDK client
	client, err := createKeyClient()
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}

	// Perform health check
	if !keyQuiet {
		fmt.Fprintf(os.Stderr, "Connecting to Secure SBOM API...\n")
	}

	if err := client.HealthCheck(ctx); err != nil {
		return fmt.Errorf("API health check failed: %w", err)
	}

	// Generate key
	if !keyQuiet {
		fmt.Fprintf(os.Stderr, "Generating new key...\n")
	}

	key, err := client.GenerateKey(ctx)
	if err != nil {
		return fmt.Errorf("failed to generate key: %w", err)
	}

	// Output result
	switch keyOutputFormat {
	case "json":
		return outputGeneratedKeyJSON(key)
	case "table":
		return outputGeneratedKeyTable(key)
	default:
		return fmt.Errorf("unsupported output format: %s", keyOutputFormat)
	}
}

func runKeyPublicCommand(cmd *cobra.Command, args []string) error {
	keyID := args[0]

	ctx, cancel := context.WithTimeout(context.Background(), keyTimeout+10*time.Second)
	defer cancel()

	// Create SDK client
	client, err := createKeyClient()
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}

	// Perform health check
	if !keyQuiet {
		fmt.Fprintf(os.Stderr, "Connecting to Secure SBOM API...\n")
	}

	if err := client.HealthCheck(ctx); err != nil {
		return fmt.Errorf("API health check failed: %w", err)
	}

	// Get public key
	if !keyQuiet {
		fmt.Fprintf(os.Stderr, "Retrieving public key for %s...\n", keyID)
	}

	publicKey, err := client.GetPublicKey(ctx, keyID)
	if err != nil {
		return fmt.Errorf("failed to get public key: %w", err)
	}

	// Output public key
	if keyOutput == "" {
		fmt.Print(publicKey)
	} else {
		if err := os.WriteFile(keyOutput, []byte(publicKey), 0644); err != nil {
			return fmt.Errorf("failed to write public key to file: %w", err)
		}
		if !keyQuiet {
			fmt.Fprintf(os.Stderr, "Public key saved to %s\n", keyOutput)
		}
	}

	return nil
}

func createKeyClient() (securesbom.ClientInterface, error) {
	// Build configuration
	config := securesbom.NewConfigBuilder().
		WithAPIKey(keyAPIKey).
		WithTimeout(keyTimeout).
		FromEnv()

	if keyBaseURL != "" {
		config = config.WithBaseURL(keyBaseURL)
	}

	baseClient, err := config.BuildClient()
	if err != nil {
		return nil, err
	}

	// Wrap with retry logic if requested
	if keyRetryCount > 0 {
		retryConfig := securesbom.RetryConfig{
			MaxAttempts: keyRetryCount,
			InitialWait: 1 * time.Second,
			MaxWait:     10 * time.Second,
			Multiplier:  2.0,
		}
		return securesbom.WithRetryingClient(baseClient, retryConfig), nil
	}

	return baseClient, nil
}

func outputKeysJSON(result *securesbom.KeyListResponse) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}

func outputKeysTable(result *securesbom.KeyListResponse) error {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	defer w.Flush()

	fmt.Fprintf(w, "KEY ID\tCREATED\tALGORITHM\n")
	fmt.Fprintf(w, "------\t-------\t---------\n")

	for _, key := range result.Keys {
		createdAt := key.CreatedAt.Format("2006-01-02 15:04")
		algorithm := key.Algorithm
		if algorithm == "" {
			algorithm = "default"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\n", key.ID, createdAt, algorithm)
	}

	if len(result.Keys) == 0 {
		fmt.Fprintf(w, "No keys found\t\t\n")
	}

	return nil
}

func outputGeneratedKeyJSON(key *securesbom.GenerateKeyCMDResponse) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(key)
}

func outputGeneratedKeyTable(key *securesbom.GenerateKeyCMDResponse) error {
	fmt.Printf("✓ New key generated successfully\n")
	fmt.Printf("Key ID: %s\n", key.ID)
	fmt.Printf("Created: %s\n", key.CreatedAt.Format(time.RFC3339))
	if key.Algorithm != "" {
		fmt.Printf("Algorithm: %s\n", key.Algorithm)
	}
	if key.PublicKey != "" {
		fmt.Printf("\nPublic Key:\n%s\n", key.PublicKey)
	}
	fmt.Printf("\nYou can now use this key ID for signing SBOMs:\n")
	fmt.Printf("  sbomasm sign --key-id %s your-sbom.json\n", key.ID)
	return nil
}
