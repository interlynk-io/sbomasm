# SecureSBOM API

`sbomasm` provides enterprise-grade cryptographic signing and verification for SBOMs through integration with
ShiftLeftCyber's SecureSBOM API. The implementation supports the standard **CycloneDX Signature Format** and 
**SPDX** detached signatures

## Why Sign SBOMs?

In today's interconnected software supply chain, SBOMs are shared across organizations, stored in repositories, and
transmitted through various channels. **Unsigned SBOMs are vulnerable** - they can be modified by malicious actors,
corrupted during transmission, or tampered with while stored, creating significant security and compliance risks.

### For SBOM Producers
Cryptographically signing your SBOMs provides:
- **Proof of authenticity** - Verify you are the legitimate creator
- **Non-repudiation** - Cannot deny creating the signed SBOM
- **Integrity assurance** - Detect any unauthorized modifications
- **Compliance confidence** - Meet regulatory requirements for supply chain security

### For SBOM Consumers  
Signature verification enables you to:
- **Trust the source** - Confirm the SBOM comes from a verified producer
- **Detect tampering** - Identify if the SBOM has been modified in transit or storage
- **Establish authenticity** - Validate the SBOM represents the actual software components
- **Maintain compliance** - Ensure your supply chain meets security standards

## Getting Started

SecureSBOM access requires an API key. Get started by:

1. **Learn more** about [ShiftLeftCyber](https://shiftleftcyber.io/) and the [SecureSBOM solution](https://shiftleftcyber.io/securesbom/)
2. **Request access** by completing the [contact form](https://shiftleftcyber.io/contactus/)
3. **Set up your environment** with the provided API credentials
4. **Start signing** your SBOMs with enterprise-grade cryptographic security

The sections below provide comprehensive guidance on implementation, from basic usage to advanced CI/CD integration.

## Overview

`sbomasm` supports the following commands to utilize the SecureSBOM API:

- `securesbomkey` - Manage cryptographic keys for signing and verification
- `sign` - Cryptographically sign an SBOM to prove authenticity
- `verify` - Verify the cryptographic signature of a signed SBOM

## Basic Usage

### Key Management

```bash
# Generate a new signing key
sbomasm securesbomkey generate

# List available keys
sbomasm securesbomkey list

# Get public key for sharing
sbomasm securesbomkey public <key-id>
```

### Signing an SBOM

```bash
sbomasm sign --key-id <your-key-id> <input-sbom>
```

### Verifying an SBOM (CycloneDX)

```bash
sbomasm verify --key-id <key-id> <signed-sbom>
```

### Verifying an SBOM (SPDX)

```bash
sbomasm verify --key-id <key-id> --signature <base64 signature> <signed-sbom>
```

## Command Options

### Sign Command

#### Required Options
- `--key-id <string>`: Key ID to use for signing the SBOM

#### Authentication Options
- `--api-key <string>`: API key for authentication (or set `SECURE_SBOM_API_KEY`)

#### Output Options
- `-o, --output <path>`: Output file path for signed SBOM
  - Default: stdout
  - Use `-` for explicit stdout output
- `-q, --quiet`: Suppress progress messages and status output

#### Network Options
- `--timeout <duration>`: Request timeout (default: 30s)
- `--retry <number>`: Number of retry attempts for failed requests (default: 3)

### Verify Command

#### Required Options
- `--key-id <string>`: Public key ID used to verify the signature

#### Required Options (SPDX Verification)
- `--signature <string>`: base64 signature of the SBOM

#### Authentication Options
- `--api-key <base64 string>`: API key for authentication (or set `SECURE_SBOM_API_KEY`)

#### Output Options
- `-q, --quiet`: Suppress output except for errors (exit code indicates success/failure)

#### Network Options
- `--timeout <duration>`: Request timeout (default: 30s)
- `--retry <number>`: Number of retry attempts for failed requests (default: 3)

### Keys Command

#### Subcommands
- `generate`: Generate a new cryptographic key pair
- `list`: List all available keys in your account
- `public <key-id>`: Retrieve the public key for sharing

## How It Works

### Signing Process

1. **Authentication**: Connects to SecureSBOM API using your API key
2. **Key Validation**: Verifies the specified key ID exists is linked to your account
3. **SBOM Processing**: Parses and validates the input SBOM format
4. **Signature Generation**: Creates a cryptographic signature using your private key
5. **Format Integration**: Embeds the signature according to format standards:
   - **CycloneDX**: Uses the standard 1.6 signature format within the SBOM
   - **SPDX**: Adds detached signature metadata
6. **Output**: Returns the signed SBOM with embedded cryptographic proof or deatached signature for SPDX

### Verification Process

1. **Signature Extraction**: Extracts the embedded signature from the signed SBOM or uses the value passed in
2. **Key Retrieval**: Fetches the corresponding public key using the key ID
3. **Hash Verification**: Validates the SBOM content against the signature
4. **Integrity Check**: Confirms the SBOM has not been modified since signing
5. **Result**: Returns verification status and signature metadata

### Key Management

The SecureSBOM API manages your cryptographic keys securely:
- **Key Generation**: Creates an ECDSA key pair
- **Secure Storage**: Private keys are securely stored in a Hardware Security Modules (HSM)
- **Access Control**: Keys are tied to your API account and access permissions
- **Public Key Sharing**: Public keys can be shared for verification purposes

## Examples

### Basic Signing and Verification

```bash
# Sign an SBOM
sbomasm sign --key-id prod-key-2024 --output signed-sbom.json sbom.json

# Verify the signed SBOM
sbomasm verify --key-id prod-key-2024 signed-sbom.json

# Verify the signed SPDX SBOM
sbomasm verify --key-id prod-key-2024 --signature "MEUCIQDmi8q+VTLgRcByA....." signed-sbom.json
```

### Environment Variables Setup

```bash
# Set up API credentials
export SECURE_SBOM_API_KEY="your-api-key-here"
```

Output example:
```
Loading signed SBOM...
Connecting to Secure SBOM API...
Verifying SBOM signature with key 045728s6-h18q-649z-67fdb-27c2afcab510...
✓ SBOM signature is VALID
Message: signature is valid
Key ID: 045728s6-h18q-649z-67fdb-27c2afcab510
Algorithm: ES256
Verified at: 2025-09-08T06:51:41-04:00
```

## Advanced Use Cases

### CI/CD Pipeline Integration

#### GitHub Actions Example

```yaml
name: Sign and Verify SBOM
on: [push]

jobs:
  sbom-security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Generate SBOM
        run: syft . -o cyclonedx-json=sbom.json
        
      - name: Sign SBOM
        env:
          SECURE_SBOM_API_KEY: ${{ secrets.SECURE_SBOM_API_KEY }}
        run: |
          sbomasm sign \
            --key-id ${{ secrets.SIGNING_KEY_ID }} \
            --output signed-sbom.json \
            sbom.json
            
      - name: Verify SBOM
        env:
          SECURE_SBOM_API_KEY: ${{ secrets.SECURE_SBOM_API_KEY }}
        run: |
          sbomasm verify \
            --key-id ${{ secrets.SIGNING_KEY_ID }} \
            signed-sbom.json
            
      - name: Upload Signed SBOM
        uses: actions/upload-artifact@v3
        with:
          name: signed-sbom
          path: signed-sbom.json
```

#### Jenkins Pipeline Example

```groovy
pipeline {
    agent any
    
    environment {
        SECURE_SBOM_API_KEY = credentials('secure-sbom-api-key')
        SIGNING_KEY_ID = 'prod-signing-key-2024'
    }
    
    stages {
        stage('Generate SBOM') {
            steps {
                sh 'syft . -o cyclonedx-json=sbom.json'
            }
        }
        
        stage('Sign SBOM') {
            steps {
                sh '''
                    sbomasm sign \
                        --key-id ${SIGNING_KEY_ID} \
                        --output signed-sbom.json \
                        sbom.json
                '''
            }
        }
        
        stage('Verify SBOM') {
            steps {
                sh '''
                    sbomasm verify \
                        --key-id ${SIGNING_KEY_ID} \
                        signed-sbom.json
                '''
            }
        }
        
        stage('Archive') {
            steps {
                archiveArtifacts artifacts: 'signed-sbom.json'
            }
        }
    }
}
```

### Batch Processing

Process multiple SBOMs in bulk:

```bash
#!/bin/bash
# batch-sign.sh

SIGNING_KEY="batch-key-2024"
INPUT_DIR="sboms"
OUTPUT_DIR="signed-sboms"

mkdir -p "$OUTPUT_DIR"

for sbom in "$INPUT_DIR"/*.json; do
    filename=$(basename "$sbom")
    echo "Signing $filename..."
    
    sbomasm sign \
        --key-id "$SIGNING_KEY" \
        --output "$OUTPUT_DIR/signed-$filename" \
        "$sbom"
        
    if [ $? -eq 0 ]; then
        echo "✓ Successfully signed $filename"
    else
        echo "✗ Failed to sign $filename"
    fi
done
```

### Supply Chain Verification

```bash
#!/bin/bash
# verify-supply-chain.sh

VENDOR_KEY="vendor-public-key"
INTERNAL_KEY="internal-key-2024"

# Verify vendor-provided SBOM
echo "Verifying vendor SBOM..."
if sbomasm verify --key-id "$VENDOR_KEY" --quiet vendor-sbom.json; then
    echo "✓ Vendor SBOM signature valid"
else
    echo "✗ Vendor SBOM signature invalid - stopping process"
    exit 1
fi

# Process and re-sign with internal key
echo "Adding internal components and re-signing..."
sbomasm merge vendor-sbom.json internal-components.json | \
    sbomasm sign --key-id "$INTERNAL_KEY" - > final-sbom.json

echo "Supply chain SBOM processing complete"
```

## Error Handling

Common error scenarios and solutions:

### Authentication Errors
```
Error: API key is required. Use --api-key flag or set SECURE_SBOM_API_KEY environment variable
```
**Solution**: Set up your API credentials properly

### Key Not Found
```
Error: key ID 'invalid-key' not found
```
**Solution**: Verify the key exists with `sbomasm keys list`

### Network Timeouts
```
Error: request timeout after 30s
```
**Solution**: Increase timeout or check network connectivity
```bash
sbomasm sign --timeout 60s --retry 5 --key-id my-key sbom.json
```

## Supported Formats

### Current Support

| Format | Version | Signing | Verification | Notes |
|--------|---------|---------|--------------|-------|
| CycloneDX | 1.6+ | ✅ | ✅ | Uses standard signature format |
| CycloneDX | 1.4-1.5 | ✅ | ✅ | Compatible with 1.6 signature format |
| SPDX | 2.3+ | ✅ | ✅ | Detached signature support |

## Future Enhancements

* **Signature Metadata**: Additional signature attributes and custom claims
* **Spport for Air Gapped Verification**: Veirfy a signed sbom offline with only the public key
* **CycloneDX Multi-Signature Support**: Multiple signatures on single SBOM
* **Signature Chain Support**: Hierarchical signature chains for supply chain trust
* **Certificate Authority (CA)** integration for key management

## Support

For any feature requests or issues related to SBOM signing and verification, use the
[following contact](https://shiftleftcyber.io/contactus/) form.

For general `sbomasm` issues, please use the [GitHub issues](https://github.com/interlynk-io/sbomasm/issues) page.
