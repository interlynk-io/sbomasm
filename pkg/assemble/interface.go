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

package assemble

import (
	"context"

	"github.com/google/uuid"
)

type Params struct {
	Ctx        *context.Context
	Input      []string
	Output     string
	ConfigPath string

	// upload requirement
	Url             string
	ApiKey          string
	Upload          bool
	UploadProjectID uuid.UUID

	Name    string
	Version string
	Type    string

	FlatMerge     bool
	HierMerge     bool
	AssemblyMerge bool
	AugmentMerge  bool

	// Augment merge specific parameters
	PrimaryFile string
	MergeMode   string // if-missing-or-empty, overwrite

	Xml  bool
	Json bool

	OutputSpec        string
	OutputSpecVersion string
}

func NewParams() *Params {
	return &Params{}
}

func Assemble(config *config) error {
	err := config.validate()
	if err != nil {
		return err
	}

	cb := newCombiner(config)

	err = cb.canCombine()
	if err != nil {
		return err
	}

	err = cb.combine()
	if err != nil {
		return err
	}
	return nil
}
