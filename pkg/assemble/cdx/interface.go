// Copyright 2023 Interlynk.io
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package cdx

import (
	"context"
	"errors"
	"strings"

	cydx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/uuid"
	"github.com/samber/lo"
)

var cdx_strings_to_types = map[string]cydx.ComponentType{
	"application":      cydx.ComponentTypeApplication,
	"container":        cydx.ComponentTypeContainer,
	"device":           cydx.ComponentTypeDevice,
	"file":             cydx.ComponentTypeFile,
	"framework":        cydx.ComponentTypeFramework,
	"library":          cydx.ComponentTypeLibrary,
	"firmware":         cydx.ComponentTypeFirmware,
	"operating-system": cydx.ComponentTypeOS,
}

var cdx_hash_algos = map[string]cydx.HashAlgorithm{
	"MD5":         cydx.HashAlgoMD5,
	"SHA-1":       cydx.HashAlgoSHA1,
	"SHA-256":     cydx.HashAlgoSHA256,
	"SHA-384":     cydx.HashAlgoSHA384,
	"SHA-512":     cydx.HashAlgoSHA512,
	"SHA3-256":    cydx.HashAlgoSHA3_256,
	"SHA3-384":    cydx.HashAlgoSHA3_384,
	"SHA3-512":    cydx.HashAlgoSHA3_512,
	"BLAKE2b-256": cydx.HashAlgoBlake2b_256,
	"BLAKE2b-384": cydx.HashAlgoBlake2b_384,
	"BLAKE2b-512": cydx.HashAlgoBlake2b_512,
	"BLAKE3":      cydx.HashAlgoBlake3,
}

func SupportedChecksums() []string {
	return lo.Keys(cdx_hash_algos)
}

func IsSupportedChecksum(algo, value string) bool {
	ualgo := strings.ToUpper(algo)
	if _, ok := cdx_hash_algos[ualgo]; ok {
		return value != ""
	}
	return false
}

type Author struct {
	Name  string
	Email string
	Phone string
}

type License struct {
	Id         string
	Expression string
}

type Supplier struct {
	Name  string
	Email string
}

type Checksum struct {
	Algorithm string
	Value     string
}

type app struct {
	Name           string
	Version        string
	Description    string
	Authors        []Author
	PrimaryPurpose string
	Purl           string
	CPE            string
	License        License
	Supplier       Supplier
	Checksums      []Checksum
	Copyright      string
}

type output struct {
	FileFormat      string
	Spec            string
	SpecVersion     string
	File            string
	Upload          bool
	UploadProjectID uuid.UUID
	Url             string
	ApiKey          string
}

type input struct {
	Files []string
}

type assemble struct {
	IncludeDependencyGraph     bool
	IncludeComponents          bool
	IncludeDuplicateComponents bool
	FlatMerge                  bool
	HierarchicalMerge          bool
	AssemblyMerge              bool
}

type MergeSettings struct {
	Ctx      *context.Context
	App      app
	Output   output
	Input    input
	Assemble assemble
}

func Merge(ms *MergeSettings) error {
	if len(ms.Output.Spec) > 0 && ms.Output.Spec != "cyclonedx" {
		return errors.New("invalid output spec")
	}

	if len(ms.Output.SpecVersion) > 0 && !validSpecVersion(ms.Output.SpecVersion) {
		return errors.New("invalid CycloneDX spec version")
	}

	merger := newMerge(ms)
	return merger.combinedMerge()
}
