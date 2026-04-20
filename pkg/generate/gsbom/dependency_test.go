// Copyright 2026 Interlynk.io
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package gsbom

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBuildDependencyGraph_Valid(t *testing.T) {
	comps := []Component{
		{Name: "libmqtt", Version: "4.3.0", PURL: "pkg:generic/acme/libmqtt@4.3.0"},
		{Name: "libtls", Version: "3.9.0", PURL: "pkg:generic/openbsd/libtls@3.9.0", DependsOn: []string{"libmqtt@4.3.0"}},
	}

	m := BuildComponentMap(comps)

	graph, warnings := BuildDependencyGraph(comps, m, nil)

	require.Len(t, warnings, 0)
	// With depends-on semantics: libtls declares it depends on libmqtt
	// So the edge is libtls@3.9.0 -> libmqtt@4.3.0
	require.Equal(t, []string{"libmqtt@4.3.0"}, graph.Edges["libtls@3.9.0"])
}

func TestBuildDependencyGraph_MissingReference(t *testing.T) {
	comps := []Component{
		{Name: "libtls", Version: "3.9.0", PURL: "pkg:generic/openbsd/libtls@3.9.0", DependsOn: []string{"missing@1.0"}},
	}

	m := BuildComponentMap(comps)

	_, warnings := BuildDependencyGraph(comps, m, nil)

	require.Len(t, warnings, 1)
}
