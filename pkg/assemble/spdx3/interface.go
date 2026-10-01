// Copyright 2025 Interlynk.io
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

package spdx3

import (
	"context"
	"errors"
	"strings"

	"github.com/interlynk-io/sbomasm/v2/pkg/sbom"
)

var spdx3_hash_algos = map[string]string{
	"MD5":         "MD5",
	"SHA-1":       "SHA1",
	"SHA-256":     "SHA256",
	"SHA-384":     "SHA384",
	"SHA-512":     "SHA512",
	"SHA3-256":    "SHA3_256",
	"SHA3-384":    "SHA3_384",
	"SHA3-512":    "SHA3_512",
	"BLAKE2b-256": "BLAKE2b_256",
	"BLAKE2b-384": "BLAKE2b_384",
	"BLAKE2b-512": "BLAKE2b_512",
	"BLAKE3":      "BLAKE3",
}

var spdx3_strings_to_purposes = map[string]string{
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
	AugmentMerge               bool
	PrimaryFile                string
	MergeMode                  string // if-missing-or-empty, overwrite
	DocLicense                 string
	IsAssemblyMergeWithPrimary bool
	IsFlatMergeWithPrimary     bool
}

// MergeSettings holds the configuration for an SPDX 3.0 merge operation.
type MergeSettings struct {
	Ctx      *context.Context
	App      app
	Output   output
	Input    input
	Assemble assemble
}

func Merge(ms *MergeSettings) error {
	if len(ms.Output.Spec) > 0 && !strings.EqualFold(ms.Output.Spec, string(sbom.SBOMSpecSPDX)) {
		return errors.New("invalid output spec")
	}

	if len(ms.Output.SpecVersion) > 0 && !validSpecVersion(ms.Output.SpecVersion) {
		return errors.New("invalid SPDX spec version")
	}

	// Handle augment merge separately
	if ms.Assemble.AugmentMerge {
		augmentMerger := newAugmentMerge(ms)
		return augmentMerger.merge()
	}

	merger := newMerge(ms)
	if ms.Assemble.IsAssemblyMergeWithPrimary || ms.Assemble.IsFlatMergeWithPrimary {
		ms.Input.Files = append([]string{ms.Assemble.PrimaryFile}, ms.Input.Files...)
	}
	merger.loadBoms()
	return merger.combinedMerge()
}

func validSpecVersion(specVersion string) bool {
	specVersion = strings.TrimPrefix(specVersion, "SPDX-")
	switch specVersion {
	case "3.0", "3.0.1":
		return true
	default:
		return false
	}
}
