// Copyright 2023 Interlynk.io
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package spdx

import (
	"context"
	"errors"

	"github.com/spdx/tools-golang/spdx"
)

var spdx_hash_algos = map[string]spdx.ChecksumAlgorithm{
	"MD5":         spdx.MD5,
	"SHA-1":       spdx.SHA1,
	"SHA-256":     spdx.SHA256,
	"SHA-384":     spdx.SHA384,
	"SHA-512":     spdx.SHA512,
	"SHA3-256":    spdx.SHA256,
	"SHA3-384":    spdx.SHA384,
	"SHA3-512":    spdx.SHA512,
	"BLAKE2b-256": spdx.BLAKE2b_256,
	"BLAKE2b-384": spdx.BLAKE2b_384,
	"BLAKE2b-512": spdx.BLAKE2b_512,
	"BLAKE3":      spdx.BLAKE3,
}

var spdx_strings_to_types = map[string]string{
	"application":      "APPLICATION",
	"framework":        "FRAMEWORK",
	"library":          "LIBRARY",
	"container":        "CONTAINER",
	"operating-system": "OPERATING-SYSTEM",
	"device":           "DEVICE",
	"firmware":         "FIRMWARE",
	"source":           "SOURCE",
	"archive":          "ARCHIVE",
	"file":             "FILE",
	"install":          "INSTALL",
	"other":            "OTHER",
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
	FileFormat  string
	Spec        string
	SpecVersion string
	File        string
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

	if len(ms.Output.Spec) > 0 && ms.Output.Spec != "spdx" {
		return errors.New("invalid output spec")
	}

	if len(ms.Output.SpecVersion) > 0 && !validSpecVersion(ms.Output.SpecVersion) {
		return errors.New("invalid CycloneDX spec version")
	}

	merger := newMerge(ms)
	merger.loadBoms()
	return merger.combinedMerge()
}
