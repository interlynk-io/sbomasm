<!--
 Copyright 2023 Interlynk.io
 
 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at
 
     http://www.apache.org/licenses/LICENSE-2.0
 
 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
-->

# `sbomasm`: Assembler for your sboms

[![Go Reference](https://pkg.go.dev/badge/github.com/interlynk-io/sbomasm.svg)](https://pkg.go.dev/github.com/interlynk-io/sbomasm)
[![Go Report Card](https://goreportcard.com/badge/github.com/interlynk-io/sbomasm)](https://goreportcard.com/report/github.com/interlynk-io/sbomasm)

`sbomasm` is your primary tool to assemble your sboms, for easy management and distribution. sboms are merged in a hierarchical manner. `sbomasm` is sbom format agnostic, it supports both spdx and cdx. 

```sh
go install github.com/interlynk-io/sbomasm@latest
```
other installation [options](#installation).

# Usage
`SPDX` assemble multiple sboms
```sh
sbomasm assemble -n "mega spdx app" -v "1.0.0" -o final-product.spdx.json sdk.spdx.json demo-app.spdx.json report.spdx.json 
```

`CDX` asseble multiple sboms
```sh
sbomasm assemble -n "mega cdx app" -v "1.0.0" -o final-product.cdx.json sbom1.json sbom2.json sbom3.json 
```

# Features
- SBOM format agnostic
- Supports Hierarchial and Flat merging
- Configurable primary component/package
- Blazing fast :rocket:

# Why should we assemble sboms? 
- `Software Supply Chain Management`: When managing the software supply chain, organizations often need to merge multiple SBOMs from different vendors or sources to create a complete and accurate picture of the software components used in their products or systems.
- `Software Development`: When developing software, teams often use multiple tools and technologies to create and manage different parts of the software stack. Merging the SBOMs from these tools can provide a holistic view of the entire software stack, making it easier to identify dependencies, vulnerabilities, and licensing issues.
- `Regulatory Compliance`: Some regulations, such as the European Union's General Data Protection Regulation (GDPR), require companies to have a clear understanding of the software components used in their systems. Merging SBOMs can provide a comprehensive view of the software stack, making it easier to comply with these regulations.
- `Open Source Software Management`: Many organizations use open source software in their products and systems. Merging SBOMs for open source components can help organizations track and manage the various dependencies, licenses, and vulnerabilities associated with these components.

# How does assembling sboms work

An assembled sbom encompasses all the components/packages, dependencies, files, licenses,  selected metadata of its included sbom. A new primary component/package is generated based on configuration, which is then associated with the included sboms primary components. 

```
+-----------------------+   +-----------------------+   +-----------------------+
|       Micro SBOM 1     |   |       Micro SBOM 2      |   |       Micro SBOM 3      |
|-----------------------|   |-----------------------|   |-----------------------|
|  Component 1           |   |  Component 3           |   |  Component 5           |
|  Component 2           |   |  Component 1           |   |  Component 6           |
|  File 1 (Comp1)        |   |  File 1 (Comp3)        |   |  File 1 (Comp5)        |
|  File 2 (Comp1)        |   |  File 2 (Comp3)        |   |                        |
|  Dependency 1 (Comp1)  |   |  Dependency 1 (Comp2)  |   |  Dependency 2 (Comp3)  |
|  License: Apache 2.0   |   |  License: MIT          |   |  License: BSD          |
|  Metadata 1            |   |  Metadata 1            |   |  Metadata 1            |
|-----------------------|   |-----------------------|   |-----------------------|
|          ↓            |   |          ↓            |   |          ↓            |
+-----------------------+   +-----------------------+   +-----------------------+
                                      ↓
                      +------------------------------------+
                      |           Mega SBOM                |
                      |------------------------------------|
                      |  Component 1                       |
                      |  Component 2                       |
                      |  Component 3                       |
                      |  Component 1                       |
                      |  Component 5                       |
                      |                                    |
                      |  File 1 (Comp1)                    |
                      |  File 2 (Comp1)                    |
                      |  File 1 (Comp3)                    |
                      |  File 2 (Comp3)                    |
                      |  File 1 (Comp5)                    |
                      |                                    |
                      |  Dependency 1 (Comp1)              |
                      |  Dependency 1 (Comp2)              |
                      |  Dependency 2 (Comp3)              |
                      |                                    |
                      |  License: Apache 2.0               |
                      |  License: MIT                      |
                      |  License: BSD                      |
                      |                                    |
                      |  Micro Sbom 1 - Primary Comp       |
                      |  Micro Sbom 2 - Primary Comp       |
                      |  Micro Sbom 3 - Primary Comp       |
                      +------------------------------------+

```

The assembled sbom spec format is guided by the input sboms e.g if the inputs are all spdx, the output needs to be spdx format.  Below is the support matrix 
for input and output formats

| Spec  | Input SBOM Formats | Output SBOM formats | Output SBOM spec version |
|----------|----------|----------| -----------------------------|
| SPDX   | json, yaml, rdf, tag-value   | json, xml   | 2.3 |
| CycloneDX  | json, xml   | json,xml   | 1.4 |


## Merge Algorithm
We currently support two algorithm 
- Hierarchical: This merge algo tries to maintain, the order of the dependent components to its primary component. For spdx this is done via relationships and for cyclonedx via nested components & dependencies. 
- Flat: As the name states, are just consolidated lists of components, dependencies, etc. 

For `spdx hierarchical merge`, all packages, dependencies, externalrefs, files are consolidates into a individual lists, no duplicates are removed. The hierarchy is maintained via dependencies. A new primary package is created, which the generated sbom describes. This primary package also adds contains
relationship between itself and the primary components of the individual sboms. 

For `cdx hierarchical merge` for each input sbom, we associate the dependent components with its primary component. This primary component, is then included as a depedenct of the newly created primary component for the assembled sbom. 

# Installation 

## Using Prebuilt binaries 

```console
https://github.com/interlynk-io/sbomasm/releases
```

## Using Homebrew
```console
brew tap interlynk-io/interlynk
brew install sbomasm
```

## Using Go install

```console
go install github.com/interlynk-io/sbomasm@latest
```

## Using repo

This approach involves cloning the repo and building it. 

1. Clone the repo `git clone git@github.com:interlynk-io/sbomasm.git`
2. `cd` into `sbomasm` folder 
3. make; make build
4. To test if the build was successful run the following command `./build/sbomasm version`


# Contributions
We look forward to your contributions, below are a few guidelines on how to submit them 

- Fork the repo
- Create your feature/bug branch (`git checkout -b feature/new-feature`)
- Commit your changes (`git commit -am "awesome new feature"`)
- Push your changes (`git push origin feature/new-feature`)
- Create a new pull-request

# Contact 
We appreciate all feedback, the best way to get in touch with us
- hello@interlynk.io
- github.com/interlynk-io/sbomasm/issues 
- https://twitter.com/InterlynkIo


# Stargazers

If you like this project, please support us by starring it. 

[![Stargazers](https://starchart.cc/interlynk-io/sbomasm.svg)](https://starchart.cc/interlynk-io/sbomasm)
