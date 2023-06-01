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

# `sbomasm`: Assembler for SBOMs

[![Go Reference](https://pkg.go.dev/badge/github.com/interlynk-io/sbomasm.svg)](https://pkg.go.dev/github.com/interlynk-io/sbomasm)
[![Go Report Card](https://goreportcard.com/badge/github.com/interlynk-io/sbomasm)](https://goreportcard.com/report/github.com/interlynk-io/sbomasm)

`sbomasm` is your primary tool to assemble SBOMs, for easy management and distribution. 

```sh
go install github.com/interlynk-io/sbomasm@latest
```
other installation [options](#installation).

# Usage
`SPDX` assemble multiple SBOMs
```sh
sbomasm assemble -n "mega spdx app" -v "1.0.0" -t "application" -o final-product.spdx.json sdk.spdx.json demo-app.spdx.json report.spdx.json 
```

`CDX` assemble multiple SBOMs
```sh
sbomasm assemble -n "mega cdx app" -v "1.0.0" -t "application" -o final-product.cdx.json sbom1.json sbom2.json sbom3.json 
```

# Features
- SBOM format agnostic
- Supports Hierarchial and Flat merging
- Configurable primary component/package
- Blazing fast :rocket:

# Why should we assemble SBOMs? 
- `Software Supply Chain Management`: When managing the software supply chain, organizations often need to merge multiple SBOMs from different vendors or sources to create a complete and accurate picture of the software components used in their products or systems.
- `Software Development`: When developing software, teams often use multiple tools and technologies to create and manage different parts of the software stack. Merging the SBOMs from these tools can provide a holistic view of the entire software stack, making it easier to identify dependencies, vulnerabilities, and licensing issues.
- `Regulatory Compliance`: Some regulations, such as the European Union's General Data Protection Regulation (GDPR), require companies to have a clear understanding of the software components used in their systems. Merging SBOMs can provide a comprehensive view of the software stack, making it easier to comply with these regulations.
- `Open Source Software Management`: Many organizations use open source software in their products and systems. Merging SBOMs for open source components can help organizations track and manage the various dependencies, licenses, and vulnerabilities associated with these components.

# How does assembling SBOMs work

An assembled SBOM encompasses all the components/packages, dependencies, files, licenses,  selected metadata of its included sbom. A new primary component/package is generated based on configuration, which is then associated with the included SBOMs primary components. 

```
+-----------------------+   +-----------------------+   +-----------------------+
|       Micro SBOM 1    |   |       Micro SBOM 2    |   |       Micro SBOM 3    |
|-----------------------|   |-----------------------|   |-----------------------|
|  Component 1          |   |  Component 3          |   |  Component 4          |
|  Component 2          |   |  Component 1          |   |  Component 5          |
|  File 1 (Comp1)       |   |  File 1 (Comp3)       |   |  File 1 (Comp5)       |
|  File 2 (Comp1)       |   |  File 2 (Comp3)       |   |                       |
|  Dependency 1 (Comp1) |   |  Dependency 1 (Comp2) |   |  Dependency 2 (Comp3) |
|  License: Apache 2.0  |   |  License: MIT         |   |  License: BSD         |
|  Metadata 1           |   |  Metadata 1           |   |  Metadata 1           |
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
                      |  Component 4                       |
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

The assembled SBOM spec format is guided by the input SBOMs e.g if the inputs are all spdx, the output needs to be spdx format.  Below is the support matrix 
for input and output formats

| Spec  | Input SBOM Formats | Output SBOM formats | Output SBOM spec version |
|----------|----------|----------| -----------------------------|
| SPDX   | json, yaml, rdf, tag-value   | json, xml   | 2.3 |
| CycloneDX  | json, xml   | json,xml   | 1.4 |


## Merge Algorithm
We currently support two algorithm 
- Hierarchical: This merge algo tries to maintain, the order of the dependent components to its primary component. For spdx this is done via relationships and for cyclonedx via nested components & dependencies. 
- Flat: As the name states, are just consolidated lists of components, dependencies, etc. 

For `spdx hierarchical merge`, all packages, dependencies, externalrefs, files are consolidates into a individual lists, no duplicates are removed. The hierarchy is maintained via dependencies. A new primary package is created, which the generated SBOM describes. This primary package also adds contains
relationship between itself and the primary components of the individual SBOMs. 

For `cdx hierarchical merge` for each input SBOM, we associate the dependent components with its primary component. This primary component, is then included as a depedenct of the newly created primary component for the assembled SBOM. 

# A complete example/use-case
Interlynk produces a variety of closed-source tools that it offers to its customers. One of its security-conscious customers recognizes the importance of being diligent about the tools running on its network and has asked Interlynk to provide SBOMs for each tool. Interlynk has complied with this request by providing individual SBOMs for each tool it ships to the customer. However, the customer soon realizes that keeping track of so many SBOMs, which they receive at regular intervals, is challenging. To address this issue, the customer automates the process by combining all the SBOMs provided by Interlynk into a single SBOM, which they can monitor more easily using their preferred tool.

The customer uses `sbomasm` to help assemble these SBOMs. The input SBOMs are the following 
```
├── sbom-tool
│   ├── sbomex-spdx.json
│   ├── sbomgr-spdx.json
│   └── sbomqs-spdx.json
```

To track all of these SBOMs, as a single unit, the first step will be to generate a config file, to capture the merged sbom details. 

`sbomasm generate > interlynk-config.yml`

The config file is a yaml document, which needs to be filled out. All the [REQUIRED] files are necessary, the [OPTIONAL] can be left blank.

```
app:
  name: 'Interlynk combined set'
  version: 'v0.0.1'
  description: 'set of binaries recv on May 04 2023'
  author:
  - name: 'customer name'
    email: 'hello@customer.com'
  primary_purpose: 'application'
  purl: '[OPTIONAL]'
  cpe: '[OPTIONAL]'
  license:
    id: '[OPTIONAL]'
  supplier:
    name: 'Interlynk'
    email: 'hello@interlynk.io'
  checksum:
  - algorithm: '[OPTIONAL]'
    value: '[OPTIONAL]'
  copyright: '[OPTIONAL]'
output:
  spec: spdx
  file_format: json
assemble:
  include_dependency_graph: true
  include_components: true
  flat_merge: false
  hierarchical_merge: true
```

After saving the file, they run the following command 
`sbomasm assemble -c interlynk-config.yml -o interlynk.combined-sbom.spdx.json samples/spdx/sbom-tool/*`

The output is an assembled SBOM for all of interlynks binaries `interlynk.combined-sbom.spdx.json`. If everything is successful, the cli command, just writes the file, and nothing is displayed to the screen. 

To get more details in case of issues or just information, run the above command with a debug flag 
`sbomasm assemble -d -c interlynk-config.yml -o interlynk.combined-sbom.spdx.json samples/spdx/sbom-tool/*`

```
2023-05-03T04:49:33.333-0700    DEBUG   assemble/config.go:313  sha256 samples/spdx/sbom-tool/sbomex-spdx.json : a0f1787b5f5b42861ec28f263be1e30c61782b7b0da1290403dedf64fffedb22
2023-05-03T04:49:33.337-0700    DEBUG   assemble/config.go:313  sha256 samples/spdx/sbom-tool/sbomgr-spdx.json : d0a0e2243b3fcaa376d95a7844c015547b98aaa5582cf740939d3fd78991a1f9
2023-05-03T04:49:33.342-0700    DEBUG   assemble/config.go:313  sha256 samples/spdx/sbom-tool/sbomqs-spdx.json : edf6fe76bb3836990d288b2a5c56d1d65aeb29b35b3f358d68ff0bd7833ce9d3
2023-05-03T04:49:33.342-0700    DEBUG   assemble/config.go:289  config &{ctx:0xc0000f7110 App:{Name:Interlynk combined set Version:v0.0.1 Description:set of binaries recv on May 04 2023 Author:[{Name:customer name Email:hello@customer.com Phone:}] PrimaryPurpose:application Purl: CPE: License:{Id: Expression:} Supplier:{Name:Interlynk Email:hello@interlynk.io} Checksums:[{Algorithm: Value:}] Copyright:} Output:{Spec:spdx FileFormat:json file:interlynk.combined-sbom.spdx.json} input:{files:[samples/spdx/sbom-tool/sbomex-spdx.json samples/spdx/sbom-tool/sbomgr-spdx.json samples/spdx/sbom-tool/sbomqs-spdx.json]} Assemble:{IncludeDependencyGraph:true IncludeComponents:true includeDuplicateComponents:true FlatMerge:false HierarchicalMerge:true}}2023-05-03T04:49:33.367-0700    DEBUG   assemble/combiner.go:50 combining 3 SPDX sboms
2023-05-03T04:49:33.378-0700    DEBUG   spdx/utils.go:53        loading bom:samples/spdx/sbom-tool/sbomex-spdx.json spec:spdx format:json
2023-05-03T04:49:33.440-0700    DEBUG   spdx/utils.go:53        loading bom:samples/spdx/sbom-tool/sbomgr-spdx.json spec:spdx format:json
2023-05-03T04:49:33.478-0700    DEBUG   spdx/utils.go:53        loading bom:samples/spdx/sbom-tool/sbomqs-spdx.json spec:spdx format:json
2023-05-03T04:49:33.523-0700    DEBUG   spdx/merge.go:114       No of Licenses: 1:  Selected:3.19
2023-05-03T04:49:33.523-0700    DEBUG   spdx/merge.go:222       primary component id: RootPackage-a3e525d1-1eca-4291-99fe-3f38223dca9b
2023-05-03T04:49:33.523-0700    DEBUG   spdx/merge.go:235       processing sbom DOCUMENT-github.com/interlynk-io/sbomex 0.0.3 with packages:74, files:1923, deps:1998, Snips:0 OtherLics:0, Annotations:0, externaldocrefs:0
2023-05-03T04:49:33.524-0700    DEBUG   spdx/merge.go:235       processing sbom DOCUMENT-github.com/interlynk-io/sbomgr 0.0.4 with packages:59, files:1004, deps:1064, Snips:0 OtherLics:0, Annotations:0, externaldocrefs:0
2023-05-03T04:49:33.525-0700    DEBUG   spdx/merge.go:235       processing sbom DOCUMENT-github.com/interlynk-io/sbomqs 0.0.14 with packages:68, files:1469, deps:1538, Snips:0 OtherLics:0, Annotations:0, externaldocrefs:0
2023-05-03T04:49:33.570-0700    DEBUG   spdx/merge.go:339       wrote sbom 3825558 bytes to interlynk.combined-sbom.spdx.json with packages:202, files:4396, deps:4598, snips:0 otherLics:0, annotations:0, externaldocRefs:0
```

The assembled SBOM can now be monitored using any SBOM monitoring tool of your choice. If you dont have one, reach out to us, we are building an SBOM monitor product, to help with this. 

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
