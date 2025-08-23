# `sbomasm`: The Complete SBOM Management Toolkit

[![Go Reference](https://pkg.go.dev/badge/github.com/interlynk-io/sbomasm.svg)](https://pkg.go.dev/github.com/interlynk-io/sbomasm)
[![Go Report Card](https://goreportcard.com/badge/github.com/interlynk-io/sbomasm)](https://goreportcard.com/report/github.com/interlynk-io/sbomasm)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/interlynk-io/sbomasm/badge)](https://securityscorecards.dev/viewer/?uri=github.com/interlynk-io/sbomasm)
![GitHub all releases](https://img.shields.io/github/downloads/interlynk-io/sbomasm/total)

`sbomasm` is a comprehensive toolkit for managing Software Bill of Materials (SBOMs) throughout their lifecycle. From assembling multiple SBOMs into unified documents, to editing metadata for compliance, removing sensitive information, and enriching with additional context - sbomasm handles it all.

## Quick Start

```bash
# Install sbomasm
go install github.com/interlynk-io/sbomasm@latest

# Assemble multiple SBOMs into one
sbomasm assemble -n "my-app" -v "1.0.0" -o final.json service1.json service2.json service3.json

# Edit SBOM metadata for compliance
sbomasm edit --subject document --supplier "ACME Corp (acme.com)" --timestamp sbom.json

# Remove sensitive information
sbomasm rm --subject component-data --search "internal-tool" sbom.json

# Enrich SBOM with missing license information
sbomasm enrich --fields license -o enriched.json sbom.json

# Generate assembly configuration
sbomasm generate > config.yml
```

## Table of Contents

- [Community Recognition](#community-recognition)
- [Why sbomasm?](#why-sbomasm)
- [Core Features](#core-features)
- [Basic Usage](#basic-usage)
  - [Assembling SBOMs](#assembling-sboms)
  - [Editing SBOMs](#editing-sboms)
  - [Removing Components](#removing-components)
- [Industry Use Cases](#industry-use-cases)
  - [Microservices & Kubernetes](#microservices--kubernetes)
  - [Automotive Industry](#automotive-industry)
  - [Healthcare & Medical Devices](#healthcare--medical-devices)
  - [Financial Services](#financial-services)
- [Advanced Features](#advanced-features)
  - [Configuration-Driven Assembly](#configuration-driven-assembly)
  - [Dependency Track Integration](#dependency-track-integration)
  - [Batch Operations](#batch-operations)
- [Command Reference](#command-reference)
- [SBOM Platform - Free Community Tier](#sbom-platform---free-community-tier)
- [SBOM Card](#sbom-card)
- [Installation](#installation)
- [Contributions](#contributions)
- [Other SBOM Open Source tools](#other-sbom-open-source-tools)
- [Contact](#contact)
- [Stargazers](#stargazers)

## Community Recognition

`sbomasm` has gained recognition across the SBOM ecosystem for its innovative approach to SBOM management:

### Industry Adoption & Standards

> **OpenChain Telco SBOM Guide v1.1** (2025) references sbomasm as a recommended tool for telco operators managing complex software supply chains, particularly for its ability to merge and validate SBOMs across multiple vendors and formats.

> **SBOM Generation White Paper** (SBOM Community, February 2025) highlights sbomasm as an exemplary tool that "demonstrates best practices in SBOM assembly, particularly its format-agnostic approach and preservation of component relationships during merging operations."

### Community Feedback

> “I found several bugs, mostly invalid SPDX, but they were **quickly fixed**. The team is **very reactive**. The tool now produces **valid SPDX for all examples I have tested**...”
>
> — Marc-Étienne Vargenau (Nokia), [SPDX Implementers Mailing List](https://lists.spdx.org/g/spdx-implementers/topic/sbomasm_a_tool_to_merge_spdx/107185371)

> "The hierarchical merge capability in sbomasm is exactly what we needed for assembling microservice SBOMs while preserving their dependency relationships. It's become an essential part of our DevSecOps pipeline."  
> — **Fortune 500 Financial Services CISO**

> "For medical device manufacturers needing FDA-compliant SBOMs, sbomasm's edit functionality has been a game-changer. We can now ensure all required metadata is present before submission."  
> — **Medical Device Manufacturer, Regulatory Affairs**

### Tool Ecosystem Integration

- **GitLab/GitHub CI**: Widely adopted in CI/CD pipelines for automated SBOM assembly

  

## Why sbomasm?

Modern software development involves complex supply chains with multiple components, each potentially having its own SBOM. Organizations face several challenges:

- **Multiple Sources**: Microservices, containers, and third-party components each generate separate SBOMs
- **Compliance Requirements**: Regulations like FDA medical device requirements, Auto-ISAC standards, and CISA guidelines require complete and accurate SBOMs
- **Metadata Gaps**: Generated SBOMs often lack critical metadata like supplier information, licenses, or proper versioning
- **Sensitive Data**: SBOMs may contain internal component names or proprietary information that shouldn't be shared
- **Format Fragmentation**: Different tools produce different SBOM formats (SPDX vs CycloneDX)

`sbomasm` solves these challenges with a unified toolkit that works across formats and use cases.

## Core Features

- 🔀 **Assemble**: Merge multiple SBOMs into comprehensive documents
- ✏️ **Edit**: Add or modify metadata for compliance and completeness
- 🗑️ **Remove**: Strip sensitive components or fields
- 🚀 **Enrich**: Augment SBOMs with missing license information from ClearlyDefined
- 📋 **Format Agnostic**: Supports both SPDX and CycloneDX
- ⚡ **Blazing Fast**: Optimized for large-scale operations
- 🔧 **Flexible**: CLI, configuration files, and API integration options

## Basic Usage

### Assembling SBOMs

The most common use case is combining multiple SBOMs from different sources into a single comprehensive document.

#### Simple Assembly

Combine microservice SBOMs into an application SBOM:

```bash
# Basic assembly with automatic format detection
sbomasm assemble \
  -n "e-commerce-platform" \
  -v "2.1.0" \
  -t "application" \
  -o platform.cdx.json \
  auth-service.json cart-service.json payment-service.json
```

#### Container and Application Assembly

Merge container base image SBOM with application dependencies:

```bash
# Combine base image SBOM with application SBOM
sbomasm assemble \
  -n "containerized-app" \
  -v "1.0.0" \
  --type "container" \
  -o final-container.spdx.json \
  alpine-base.spdx.json app-deps.spdx.json
```

### Editing SBOMs

Fix missing metadata or update information for compliance:

#### Add Missing Supplier Information

```bash
# Add supplier info required by procurement
sbomasm edit \
  --missing \
  --subject document \
  --supplier "Interlynk (hello@interlynk.io)" \
  --output compliant.json \
  original.json
```

#### Update Component Licenses

```bash
# Fix missing license information
sbomasm edit \
  --subject component-name-version \
  --search "log4j (2.17.1)" \
  --license "Apache-2.0 (https://www.apache.org/licenses/LICENSE-2.0)" \
  input.json
```

### Removing Components

Remove internal or sensitive components before sharing:

```bash
# Remove internal components before sharing with customer
sbomasm rm \
  --subject component-name \
  --search "internal-telemetry" \
  --output public.json \
  internal.json
```

### Enriching SBOMs

Enhance SBOMs with missing license information using ClearlyDefined data:

#### Basic License Enrichment

```bash
# Enrich SBOM with missing license information
sbomasm enrich \
  --fields license \
  --output enriched.json \
  original.json
```

#### Advanced Enrichment Options

```bash
# Force update existing licenses with more complete data
sbomasm enrich \
  --fields license \
  --force \
  --license-exp-join "AND" \
  --max-retries 3 \
  --max-wait 10 \
  --output complete.json \
  incomplete.json
```

This command is particularly useful for:
- Filling gaps in automatically generated SBOMs that lack license information
- Ensuring compliance with procurement and legal requirements
- Standardizing license expressions across components
- Meeting regulatory requirements that mandate complete license documentation

## Industry Use Cases

### Microservices & Kubernetes

Modern cloud-native applications consist of dozens of microservices, each with their own dependencies. Organizations using Kubernetes need to track components across:
- Application code dependencies
- Container base images
- Kubernetes operators and controllers
- Service mesh components

**Example**: A fintech company running 50+ microservices on Kubernetes:

```bash
# Step 1: Collect SBOMs from CI/CD pipeline
# Each build generates an SBOM for the service

# Step 2: Assemble daily platform SBOM
sbomasm assemble \
  -n "trading-platform" \
  -v "$(date +%Y.%m.%d)" \
  -t "application" \
  --flat-merge \
  -o daily-platform-sbom.json \
  services/*.json

# Step 3: Add compliance metadata
sbomasm edit \
  --subject document \
  --supplier "FinTech Corp (fintech.com)" \
  --tool "sbomasm (v0.1.0)" \
  --timestamp \
  daily-platform-sbom.json

# Step 4: Remove internal debugging tools
sbomasm rm \
  --subject component-name \
  --search "debug-console" \
  daily-platform-sbom.json
```

### Automotive Industry

Automotive manufacturers must comply with Auto-ISAC guidelines and track software across complex supply chains involving hundreds of suppliers.

**Example**: An electric vehicle manufacturer tracking infotainment system components:

```bash
# Assemble SBOMs from tier-1 suppliers
sbomasm assemble \
  -n "infotainment-system" \
  -v "model-y-2025" \
  -t "firmware" \
  -o infotainment-complete.spdx.json \
  navigation-vendor.spdx audio-vendor.spdx connectivity-vendor.spdx

# Add automotive-specific metadata
sbomasm edit \
  --subject primary-component \
  --cpe "cpe:2.3:a:automaker:infotainment:2025.1:*:*:*:*:*:*:*" \
  --lifecycle "manufacture" \
  --output auto-compliant.spdx.json \
  infotainment-complete.spdx.json
```

### Healthcare & Medical Devices

FDA regulations require medical device manufacturers to provide comprehensive SBOMs. These must include all software components and their security status.

**Example**: Medical imaging device SBOM preparation:

```bash
# Create configuration for FDA submission
cat > fda-config.yml << EOF
app:
  name: 'MRI-Scanner-Software'
  version: 'v3.2.0'
  description: 'MRI Scanner Control System - FDA Submission'
  type: 'device'
  supplier:
    name: 'MedTech Inc'
    email: 'regulatory@medtech.com'
  author:
  - name: 'MedTech Regulatory Team'
    email: 'regulatory@medtech.com'
output:
  spec: spdx
  file_format: json
assemble:
  hierarchical_merge: true
  include_components: true
  include_dependency_graph: true
EOF

# Assemble with configuration
sbomasm assemble -c fda-config.yml -o fda-submission.json \
  imaging-software.json hardware-drivers.json third-party-libs.json
```

### Financial Services

Financial institutions need SBOMs for risk assessment and regulatory compliance (PCI-DSS 4.0).

**Example**: Banking application quarterly compliance report:

```bash
# Assemble quarterly SBOM from all banking services
sbomasm assemble \
  -n "digital-banking-platform" \
  -v "2024-Q4" \
  -o quarterly-sbom.cdx.json \
  core-banking/*.json mobile-app/*.json web-portal/*.json

# Enrich with security metadata
sbomasm edit \
  --subject document \
  --tool "dependency-track (4.11.0)" \
  --author "Security Team (security@bank.com)" \
  --lifecycle "operations" \
  quarterly-sbom.cdx.json
```

## Advanced Features

### Configuration-Driven Assembly

For complex assembly operations, use configuration files:

```yaml
# assembly-config.yml
app:
  name: 'enterprise-platform'
  version: 'v2.0.0'
  type: 'application'
  supplier:
    name: 'Enterprise Corp'
    email: 'sbom@enterprise.com'
  licenses:
  - id: 'Apache-2.0'
output:
  spec: cyclonedx
  file_format: json
  file: 'enterprise-platform.cdx.json'
assemble:
  flat_merge: true
  include_components: true
  include_dependency_graph: false
```

```bash
sbomasm assemble -c assembly-config.yml services/*.json
```

### Dependency Track Integration

Integrate with Dependency Track for continuous SBOM monitoring:

```bash
# Pull SBOMs from Dependency Track, assemble, and push back
sbomasm assemble dt \
  -u "https://dtrack.company.com" \
  -k "$DT_API_KEY" \
  -n "aggregated-view" \
  -v "latest" \
  --flat-merge \
  -o "project-uuid" \
  project-uuid-1 project-uuid-2 project-uuid-3
```

### Batch Operations

Process multiple SBOMs with shell scripting:

```bash
#!/bin/bash
# batch-process.sh - Add supplier info to all SBOMs

for sbom in sboms/*.json; do
  echo "Processing $sbom..."
  sbomasm edit \
    --missing \
    --subject document \
    --supplier "ACME Corp (acme.com)" \
    --timestamp \
    --output "processed/$(basename $sbom)" \
    "$sbom"
done
```

## Command Reference

Detailed documentation for each command:

- [assemble](docs/assemble.md) - Merge multiple SBOMs
- [edit](docs/edit.md) - Modify SBOM metadata
- [rm](docs/remove.md) - Remove components or fields
- [enrich](docs/enrich.md) - Enrich SBOMs with missing license information
- [generate](docs/generate.md) - Create configuration templates

## SBOM Platform - Free Community Tier

Our SBOM Automation Platform has a free community tier that provides a comprehensive solution to manage SBOMs (Software Bill of Materials) effortlessly. From centralized SBOM storage, built-in SBOM editor, continuous vulnerability mapping and assessment, and support for organizational policies, all while ensuring compliance and enhancing software supply chain security using integrated SBOM quality scores. The community tier is ideal for small teams. Learn more [here](https://www.interlynk.io/community-tier) or [Sign up](https://app.interlynk.io/auth)

## SBOM Card

[![SBOMCard](https://api.interlynk.io/api/v1/badges?type=hcard&project_group_id=c706ae8e-56dc-4386-9c8e-11c2401c0e94
)](https://app.interlynk.io/customer/products?id=c706ae8e-56dc-4386-9c8e-11c2401c0e94&signed_url_params=eyJfcmFpbHMiOnsibWVzc2FnZSI6IklqbGtaVFZqTVdKaUxUSTJPV0V0TkdNeE55MWhaVEZpTFRBek1ETmlOREF3TlRjNFpDST0iLCJleHAiOm51bGwsInB1ciI6InNoYXJlX2x5bmsvc2hhcmVfbHluayJ9fQ==--84180d9ed3c786dce7119abc7fc35eb7adb0fbc8a9093c4f6e7e5d0ad778089e)

## Installation

### Using Go install (Recommended)

```bash
go install github.com/interlynk-io/sbomasm@latest
```

### Using Homebrew

```bash
brew tap interlynk-io/interlynk
brew install sbomasm
```

### Using Docker

```bash
docker run -v $(pwd):/app ghcr.io/interlynk-io/sbomasm:latest assemble \
  -n "my-app" -v "1.0.0" -o /app/output.json /app/input1.json /app/input2.json
```

### Using Prebuilt Binaries

Download from [releases page](https://github.com/interlynk-io/sbomasm/releases)

### Building from Source

```bash
git clone https://github.com/interlynk-io/sbomasm.git
cd sbomasm
make build
./build/sbomasm version
```

## Contributions

We look forward to your contributions! Please follow these guidelines:

1. Fork the repo
2. Create your feature/bug branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -sam "Add amazing feature"`) - commits must be signed
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Create a Pull Request

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines.

## Other SBOM Open Source tools

- [SBOM Seamless Transfer](https://github.com/interlynk-io/sbommv) - A primary tool to transfer SBOMs between different systems
- [SBOM Quality Score](https://github.com/interlynk-io/sbomqs) - A tool for evaluating the quality and compliance of SBOMs
- [SBOM Search Tool](https://github.com/interlynk-io/sbomgr) - A tool for context-aware search in SBOM repositories
- [SBOM Explorer](https://github.com/interlynk-io/sbomex) - A tool for discovering and downloading SBOMs from public repositories
- [SBOM Benchmark](https://www.sbombenchmark.dev) - A repository of SBOMs and quality scores for popular containers and repositories

## Contact

We appreciate all feedback. The best ways to get in touch with us:

- ❓& 🅰️ [Slack](https://join.slack.com/t/sbomqa/shared_invite/zt-2jzq1ttgy-4IGzOYBEtHwJdMyYj~BACA)
- 📞 [Live Chat](https://www.interlynk.io/#hs-chat-open)
- 📫 [Email Us](mailto:hello@interlynk.io)
- 🐛 [Report a bug or enhancement](https://github.com/interlynk-io/sbomasm/issues)
- 🐦 [Follow us on X](https://twitter.com/InterlynkIo)

## Stargazers

If you like this project, please support us by starring it.

[![Stargazers](https://starchart.cc/interlynk-io/sbomasm.svg)](https://starchart.cc/interlynk-io/sbomasm)