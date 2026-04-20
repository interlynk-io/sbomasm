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

import "testing"

func TestFilterComponents(t *testing.T) {
	input := []Component{
		{Name: "libmqtt", Version: "4.3.0", PURL: "pkg:generic/acme/libmqtt@4.3.0", Tags: []string{"display"}},
		{Name: "libtls", Version: "3.9.0", PURL: "pkg:generic/openbsd/libtls@3.9.0", DependsOn: []string{"libmqtt@4.3.0"}, Tags: []string{"core", "networking"}},
	}

	out := FilterComponents(input, []string{"core"}, nil)

	if len(out) != 1 || out[0].Name != "libtls" {
		t.Fatalf("filter failed")
	}
}

func TestFilterComponents_ExcludeTag(t *testing.T) {
	input := []Component{
		{Name: "libmqtt", Version: "4.3.0", PURL: "pkg:generic/acme/libmqtt@4.3.0", Tags: []string{"display"}},
		{Name: "libtls", Version: "3.9.0", PURL: "pkg:generic/openbsd/libtls@3.9.0", DependsOn: []string{"libmqtt@4.3.0"}, Tags: []string{"core", "networking"}},
	}

	out := FilterComponents(input, nil, []string{"core"})

	if len(out) != 1 || out[0].Name != "libmqtt" {
		t.Fatalf("filter failed")
	}
}
