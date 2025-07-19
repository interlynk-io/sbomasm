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

package types

type RemovalKind string

const (
	FieldRemoval      RemovalKind = "field"
	ComponentRemoval  RemovalKind = "component"
	DependencyRemoval RemovalKind = "dependency"
)

type SCOPE string

const (
	DOCUMENT   SCOPE = "document"
	COMPONENT  SCOPE = "component"
	DEPENDENCY SCOPE = "dependency"
)

type RmParams struct {
	Kind                 RemovalKind
	Field                string
	Scope                string
	Key                  string
	Value                string
	All                  bool
	ComponentName        string
	ComponentVersion     string
	DependencyID         string
	IsComponent          bool
	IsDependency         bool
	IsKeyPresent         bool
	IsValuePresent       bool
	IsKeyAndValuePresent bool
	DryRun               bool
	Summary              bool
	OutputFile           string
}
