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

func TestDeduplicateComponents(t *testing.T) {
	input := []Component{
		{Name: "libmqtt", Version: "4.3.0", PURL: "pkg:generic/acme/libmqtt@4.3.0"},
		{Name: "libtls", Version: "3.9.0", PURL: "pkg:generic/openbsd/libtls@3.9.0", DependencyOf: []string{"libmqtt@4.3.0"}},
		{Name: "libmqtt", Version: "4.3.0", PURL: "pkg:generic/acme/libmqtt@4.3.0"},
		{Name: "libtls", Version: "3.9.0", PURL: "pkg:generic/openbsd/libtls@3.9.0", DependencyOf: []string{"libmqtt@4.3.0"}},
	}

	out, warns := DeduplicateComponents(input)

	if len(out) != 2 {
		t.Fatalf("expected 1 component, got %d", len(out))
	}

	if len(warns) == 0 {
		t.Fatalf("expected warning for duplicate")
	}
}
