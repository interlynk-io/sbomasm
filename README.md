<!--
 Copyright 2023 Interlynk.io

 SPDX-License-Identifier: Apache-2.0

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
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/interlynk-io/sbomasm/badge)](https://securityscorecards.dev/viewer/?uri=github.com/interlynk-io/sbomasm)
![GitHub all releases](https://img.shields.io/github/downloads/interlynk-io/sbomasm/total)

`sbomasm` is your primary tool to assemble and edit SBOMs, for easy management and distribution.

```sh
go install github.com/interlynk-io/sbomasm@latest
```
other installation [options](#installation).

# SBOM Platform - Free Tier

Our SBOM Automation Platform has a new free tier that provides a comprehensive solution to manage SBOMs (Software Bill of Materials) effortlessly. From centralized SBOM storage, built-in SBOM editor, continuous vulnerability mapping and assessment, and support for organizational policies, all while ensuring compliance and enhancing software supply chain security using integrated SBOM quality scores. The free tier is ideal for small teams. [Sign up](https://app.interlynk.io/)


# SBOM Card
[![SBOMCard](https://api.interlynk.io/api/v1/badges?type=hcard&project_group_id=c706ae8e-56dc-4386-9c8e-11c2401c0e94
)](https://app.interlynk.io/customer/products?id=c706ae8e-56dc-4386-9c8e-11c2401c0e94&signed_url_params=eyJfcmFpbHMiOnsibWVzc2FnZSI6IklqbGtaVFZqTVdKaUxUSTJPV0V0TkdNeE55MWhaVEZpTFRBek1ETmlOREF3TlRjNFpDST0iLCJleHAiOm51bGwsInB1ciI6InNoYXJlX2x5bmsvc2hhcmVfbHluayJ9fQ==--84180d9ed3c786dce7119abc7fc35eb7adb0fbc8a9093c4f6e7e5d0ad778089e)

# Usage

### Assemle SBOMs
```sh
`SPDX` assemble multiple SBOMs
```sh
sbomasm assemble -n "mega spdx app" -v "1.0.0" -t "application" -o final-product.spdx.json sdk.spdx.json demo-app.spdx.json report.spdx.json
```
`CDX` assemble multiple SBOMs
```sh
sbomasm assemble -n "mega cdx app" -v "1.0.0" -t "application" -o final-product.cdx.json sbom1.json sbom2.json sbom3.json
```
`sbomasm` in an AirGapped Environment
```sh
INTERLYNK_DISABLE_VERSION_CHECK=true sbomasm assemble -n "mega cdx app" -v "1.0.0" -t "application" -o final-product.cdx.json sbom1.json sbom2.json sbom3.json
```
`sbomasm` via containers
```sh
docker run -v .:/app/sboms/ ghcr.io/interlynk-io/sbomasm:v0.1.3 assemble -n "assemble cdx app" -v "v2.0.0" -t "application" -o /app/sboms/final-prod.cdx.json /app/sboms/one.cdx.json /app/sboms/two.cdx.json
```
`CDX` assemble multiple SBOMs and limit output cyclonedx version
```sh
sbomasm assemble -n "mega cdx app" -v "1.0.0" -t "application" -e 1.4 -o final-product.cdx.json sbom1.json sbom2.json sbom3.json
```

#### Dependency Track Integration 

Assemble 2 projects from DT into a flat merged assembled sbom, and save the file to local disk.
```sh
sbomasm assemble dt -d -u "http://localhost:8081/" -k "odt_EpqhWc1Meuc50VeD0w5fuyKELt5dbCUb" -n "mega-app" -v "1.0.0
" -t "application" -f -o merged_sbom.json  08c2777b-bc4f-4b98-be54-e3f901736d71 9d94d566-a20c-4b65-b1b8-18dc4e238a55
```

Assemble 2 projects from DT using flat merge and push the assembled sbom to another project 
```sh 
./build/sbomasm assemble dt -d -u "http://localhost:8081/" -k "odt_EpqhWc1Meuc50VeD0w5fuyKELt5dbCUb" -n "mega-app" -v "1.0.0
" -t "application"  -f -o 1379d800-abb0-498b-a6e5-533318670e40  08c2777b-bc4f-4b98-be54-e3f901736d71 9d94d566-a20c-4b65-b1b8-18dc4e238a55
```

### Edit SBOMs
Change the name and version of the primary component.
```sh
sbomasm edit --subject primary-component --name "cool-app" --version "v1.0.0" --type "application" --output cool-app-mod.spdx.json cool-app.spdx.json
```

Add supplier information & timestamp to the document, if missing.
```sh
sbomasm edit --missing --subject document --timestamp --supplier "interlynk (support@interlynk.io)" in-sbom-cdx.json
```

Append a new author to the primary component.
```sh
sbomasm edit --append --subject primary-component --author "abc (abc@gmail.com)" in-sbom-2.json
```

Find a component by name & version and add update its purl
```sh
 sbomasm edit --subject component-name-version --search "abc (v1.0.0)" --purl "pkg:deb/debian/abc@1.0.0" in-sbom-3.json
```

# Features
- SBOM format agnostic
- Supports Hierarchial/Flat and Assemble merging
- Configurable primary component/package
- Edit metadata for SBOMs
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

The assembled SBOM spec format is guided by the input SBOMs e.g if the inputs are all SPDX, the output needs to be SPDX format.  Below is the support matrix
for input and output formats

| Spec  | Input SBOM Formats | Output SBOM formats | Output SBOM spec version |
|----------|----------|----------| -----------------------------|
| SPDX   | json, yaml, rdf, tag-value   | json, xml   | 2.3 |
| CycloneDX  | json, xml                | json, xml   | 1.6 |


## Merge Algorithm
The default merge algorithm is `Hierarchical` merge.

| Algo  | SBOM Spec| Duplicates | Notes |
|----------|----------|------|----------|
| Hierarchical   | CycloneDX  | Not Removed | For each input SBOM, we associate the dependent components with its primary component. This primary component is then included as a dependent of the newly created primary component for the assembled SBOM|
| Flat  | CycloneDX   | Removed | Provides a flat list of components |
| Assembly | CycloneDX | Removed | Similar to Hierarchical merge, but treats each sbom as not dependent, so no relationships are created with primary.  |
| Hierarchical   | SPDX  | Not Removed | It maintains relationships among all the merged documents. Contains relationship is using to express dependencies. No duplicate components are removed.|
| Flat  | SPDX   | Not Removed | It creates a flat list of all packages and files. It removes all relationships except the describes relationship|
| Assembly | SPDX | Not Removed | Similar to Hierarchical, except the contains relationship is omitted |

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

The assembled SBOM can now be monitored using any SBOM monitoring tool of your choice. If you don't have one, contact us, we are building an SBOM monitor product to help with this.


# Edit
The edit command allows you to modify an existing Software Bill of Materials (SBOM) by filling in gaps or adding information that may have been missed during the generation process. This command operates by first locating the entity to edit and then adding the required information. The goal of edit is not to provide a full editing experience but to help fill in filling in missing information useful for compliance and security purposes

## How it works
The edit command works based on locating entities and then modifying their metadata.

We support locating the following entities.
- *Document*: This is the SBOM itself.
- *Primary Component*: The primary component described by the SBOM.
- *Any Component via search*: Any component or package described by the SBOM, which can be located by name & version.

We support the following modifications operations
- *Overwrite (default)*: This operation replaces the existing value.
- *Append*: This operation appends the new value to the existing value.
- *Missing*: This operation is only applied if the field or value is missing.

## Fields supported

`Document`
| Input Param  | Input Format | CDX Spec Field | SPDX Spec field |
|----------|----------|----------| -----------------------------|
| author   | "name (email)"   |  Metadata->authors   | CreationInfo->Creator->Person|
| supplier | "name (url)"   |  Metadata->Supplier   | CreationInfo->Creator->Comment |
| tool | "name (version)"   |  Metadata->Tools   | CreationInfo->Creator->Tool |
| lifecycle | "build" | Metadata->lifecycles->phase   | - |
| type | "application" | -  | - |
| name | "name" |  -   | - |
| version | "1.0.0" |  -   | - |
| description | "description" |  -   | DocumentComment |
| copyright| "abc @2023" | -   | - |
| repository | "github.com/interlynk/sbomasm"| bom->externalreferences | - |
| cpe | "cpe:2.3:a:apache:tomcat:9.0.0:*:*:*:*:*:*:*" | -  | - |
| purl| "pkg:github/apache/tomcat@9.0.0" | -  | - |
| hash | "MD5 (1234567890)" | -   | - |
| license | "MIT (mit.edu/~amini/LICENSE.md)" | Metadata->Licenses   | DataLicense |
| timestamp | "2023-05-03T04:49:33.378-0700" | Metadata->timestamp  | CreationInfo->Created |


`Primary Component & Component Name Version`
| Input Param  | Input Format | CDX Spec Field | SPDX Spec field |
|----------|----------|----------| -----------------------------|
| author   | "name (email)"   |  Comp->authors or author  | - |
| supplier | "name (url)"   |  Comp->Supplier   | Pkg->Supplier |
| tool | "name (version)"   |  -   | - |
| lifecycle | "build" | - | - |
| type | "application" | Comp->Type  | Pkg->PrimaryPackagePurpose |
| name | "name" |  Comp->name   | Pkg->PackageName |
| version | "1.0.0" |  Comp->version   | Pkg->PackageVersion |
| description | "description" |  Comp->Description   | Pkg->PackageDescription |
| copyright| "abc @2023" | Comp->copyright  | pkg->copyright |
| repository | "github.com/interlynk/sbomasm"| Comp->externalreferences | Pkg->PackageDownloadLocation |
| cpe | "cpe:2.3:a:apache:tomcat:9.0.0:*:*:*:*:*:*:*" | Comp->cpe  | Pkg->ExternalReferences->Security |
| purl| "pkg:github/apache/tomcat@9.0.0" | Comp->purl  | Pkg->ExternalReferences->PackageManager |
| hash | "MD5 (1234567890)" | Comp->hashes   | Pkg->Checksums |
| license | "MIT (mit.edu/~amini/LICENSE.md)" | Comp->Licenses   | Pkg->ConcludedLicense |
| timestamp | "2023-05-03T04:49:33.378-0700" | -  | - |


## Searching for a component

Edit allows you to search for a component to edit. Currently you can only search for a component by its name & version.

```sh
sbomasm edit --subject component-name-version --search "apache tomcat (9.0.0)" --name "apache tomcat" --version "9.0.0" --author "apache" --license "Apache-2.0" --supplier "apache.org" --repository "github.com/apache/tomcat" --cpe "cpe:2.3:a:apache:tomcat:9.0.0:*:*:*:*:*:*:*" --purl "pkg:github/apache/tomcat@9.0.0" --hash "MD5 (1234567890)" in-cdx.json
```

In the above command, the subject indicate the type of search to use, and the search parameter is the format of the search string. The format is
`name (version)`. The name and version are required fields.

## Things to know
- Edit never modifies the original SBOM, it creates a new SBOM with the modifications.
- Every edit operation changes the serial number in CDX spec.
- Edit attempts to write out the SBOM in the same format it was read in. Only SPDX rdf & xml cannot be serialized out.

## Example
The primary use-case this was build for is to augment recently merged sboms or fix sboms which have know bad metadata. In your CICD pipeline
once you merge two sboms using sbomasm, you would like to provide more metadata to its primary component to meet compliance
standards. e.g you would like to add supplier, author, license data.

`Step 1`: Merge the sboms
```sh
sbomasm assemble -n "mega cdx app" -v "1.0.0" -t "application" -o final-product.cdx.json sbom1.json sbom2.json sbom3.json
```

`Step 2`: Edit the document metadata add in 2 authors, a supplier, a tool, a license, a repository, and update the timestamp and write out the final sbom to a new sbom.

```sh
sbomasm edit --subject document --author "fred (fred@c.com)" --author "jane (jane@c.com)" --supplier "interlynk.io (https://interlynk.io)" --tool "sbomasm edit (v1.0.0)" --license "Apache-2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)" --repository "github.com/interlynk/cool-app" --timestamp" -o final-mod-product.json final-product.cdx.json
```

`Step 3`: Edit the primary component, set its version to be the one provided by ENV, and also update its PURL as the sbom-generate wrote out a malformed one.

```sh
sbomasm edit --subject primary-component --purl "pkg:golang/interlynk/cool-app@1.0.0" --version "$PRODUCT_VERSION" -o final-mod-primary-product.json final-mod-product.json
```

`Step 4`: Edit some components which are missing license data, which we know it should be Apache-2.0

```bash
edit_components() {
    for component in "$@"; do
        name=$(echo "$component" | cut -d',' -f1)
        version=$(echo "$component" | cut -d',' -f2 | sed 's/\s//g')
        sbomasm edit --subject component-name-version --search "$name ($version)" --license "Apache-2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)" -o final-mod-primary-product.json final-mod-primary-product.json
    done
}

components=("demo-lib, v1.0.0" "third-party-lib, v2.1.3" "local-lib, v0.9.2")
edit_components "${components[@]}"
```

`Step 5`: Upload the final-mod-primary-product.json to your artifact for vuln scanning and compliance checks to Interlynk Platform.

```bash
python3 ${{ env.PYLYNK_TEMP_DIR }}/pylynk.py --verbose upload --prod ${{env.TOOL_NAME}} --env ${{ env.SBOM_ENV }} --sbom final-mod-pimary-product.json --token ${{ secrets.INTERLYNK_SECURITY_TOKEN }}
```

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
3. `make; make build`
4. To test if the build was successful run the following command `./build/sbomasm version`


# Contributions
We look forward to your contributions, below are a few guidelines on how to submit them

- Fork the repo
- Create your feature/bug branch (`git checkout -b feature/bug`)
- Commit your changes (`git commit -aSm "awesome new feature"`) - commits must be signed
- Push your changes (`git push origin feature/new-feature`)
- Create a new pull-request

# Other SBOM Open Source tools
- [SBOM Quality Score](https://github.com/interlynk-io/sbomqs) - Quality & Compliance tool
- [SBOM Search Tool](https://github.com/interlynk-io/sbomgr) - Search Tool
- [SBOM Explorer](https://github.com/interlynk-io/sbomex) - Discovering and downloading SBOM from a public repository
- [SBOM Benchmark](https://www.sbombenchmark.dev) is a repository of SBOM and quality score for most popular containers and repositories

# Contact
We appreciate all feedback. The best ways to get in touch with us:
- ❓& 🅰️ [Slack](https://join.slack.com/t/sbomqa/shared_invite/zt-2jzq1ttgy-4IGzOYBEtHwJdMyYj~BACA)
- :phone: [Live Chat](https://www.interlynk.io/#hs-chat-open)
- 📫 [Email Us](mailto:hello@interlynk.io)
- 🐛 [Report a bug or enhancement](https://github.com/interlynk-io/sbomasm/issues)
- :x: [Follow us on X](https://twitter.com/InterlynkIo)

# Stargazers

If you like this project, please support us by starring it.

[![Stargazers](https://starchart.cc/interlynk-io/sbomasm.svg)](https://starchart.cc/interlynk-io/sbomasm)
