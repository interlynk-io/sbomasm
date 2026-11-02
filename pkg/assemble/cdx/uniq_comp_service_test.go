// Copyright 2026 Interlynk.io
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

package cdx

import (
	"context"
	"reflect"
	"testing"

	cydx "github.com/CycloneDX/cyclonedx-go"
)

const (
	iarVersion  = "9.70.1.475"
	zlibVersion = "1.3.1"
	sbom1Zlib   = "sbom1-zlib"
	sbom2Zlib   = "sbom2-zlib"
	zlibPURL    = "pkg:generic/zlib@" + zlibVersion
)

func zlib(ref string) *cydx.Component {
	return &cydx.Component{BOMRef: ref, Type: cydx.ComponentTypeLibrary, Name: "zlib", Version: zlibVersion, PackageURL: zlibPURL}
}

// A purl names a package, so distinct components can share one: for example
// two architecture builds of the same library. Reusing the purl as bom-ref
// must not give them the same reference.
func TestStoreAndCloneWithNewIDKeepsBomRefsUnique(t *testing.T) {
	const purl = "pkg:generic/iar-math-library@" + iarVersion
	inputs := []cydx.Component{
		{BOMRef: "a", Type: cydx.ComponentTypeLibrary, Name: "IAR Math Library", Version: iarVersion, PackageURL: purl},
		{BOMRef: "b", Type: cydx.ComponentTypeLibrary, Name: "m7M_tl", Version: iarVersion, PackageURL: purl},
		{BOMRef: "c", Type: cydx.ComponentTypeFile, Name: "m7M_tl", Version: iarVersion, PackageURL: purl},
		*zlib("d"),
	}
	want := map[string]string{
		"a": purl,
		"b": "m7M_tl@" + iarVersion,
		"c": "m7M_tl@" + iarVersion + "-2",
		"d": zlibPURL,
	}

	s := newUniqueComponentService(context.Background())
	for i := range inputs {
		got, dup := s.StoreAndCloneWithNewID(&inputs[i])
		if dup {
			t.Fatalf("%s reported as duplicate", inputs[i].BOMRef)
		}
		if got.BOMRef != want[inputs[i].BOMRef] {
			t.Errorf("%s bom-ref = %q, want %q", inputs[i].BOMRef, got.BOMRef, want[inputs[i].BOMRef])
		}
		if resolved, ok := s.ResolveDepID(inputs[i].BOMRef); !ok || resolved != want[inputs[i].BOMRef] {
			t.Errorf("%s resolves to %q, want %q", inputs[i].BOMRef, resolved, want[inputs[i].BOMRef])
		}
	}
}

// The same component from two input SBOMs still merges into one.
func TestStoreAndCloneWithNewIDMergesSameComponent(t *testing.T) {
	s := newUniqueComponentService(context.Background())
	first, _ := s.StoreAndCloneWithNewID(zlib(sbom1Zlib))
	second, dup := s.StoreAndCloneWithNewID(zlib(sbom2Zlib))
	if !dup || second.BOMRef != first.BOMRef || first.BOMRef != zlibPURL {
		t.Fatalf("first=%q second=%q dup=%v", first.BOMRef, second.BOMRef, dup)
	}
}

// Two input refs that merged into one component must not repeat that
// component in a dependsOn list; CycloneDX requires the items to be unique.
func TestResolveDepIDsDropsRepeats(t *testing.T) {
	s := newUniqueComponentService(context.Background())
	s.StoreAndCloneWithNewID(zlib(sbom1Zlib))
	s.StoreAndCloneWithNewID(zlib(sbom2Zlib))
	s.StoreAndCloneWithNewID(&cydx.Component{BOMRef: "sbom1-lua", Type: cydx.ComponentTypeLibrary, Name: "lua", Version: "5.3.5"})

	got := s.ResolveDepIDs([]string{sbom1Zlib, "sbom1-lua", sbom2Zlib, "unknown"})
	if want := []string{zlibPURL, "lua@5.3.5"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("ResolveDepIDs = %v, want %v", got, want)
	}
}
