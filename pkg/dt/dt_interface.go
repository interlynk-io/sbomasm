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

package dt

import (
	"context"
	"fmt"
	"os"

	dtrack "github.com/DependencyTrack/client-go"
	"github.com/google/uuid"
	"github.com/interlynk-io/sbomasm/v2/pkg/logger"
)

type Params struct {
	Url             string
	ApiKey          string
	ProjectIds      []uuid.UUID
	UploadProjectID uuid.UUID

	Ctx    *context.Context
	Input  []string
	Output string
	Upload bool

	Name    string
	Version string
	Type    string

	FlatMerge     bool
	HierMerge     bool
	AssemblyMerge bool

	Xml  bool
	Json bool

	OutputSpec        string
	OutputSpecVersion string
}

func NewParams() *Params {
	return &Params{}
}

func (dtP *Params) PopulateInputField(ctx context.Context) {
	log := logger.FromContext(ctx)

	log.Debugf("Config: %+v", dtP)

	dTrackClient, err := dtrack.NewClient(dtP.Url,
		dtrack.WithAPIKey(dtP.ApiKey), dtrack.WithDebug(false))
	if err != nil {
		log.Fatalf("Failed to create Dependency-Track client: %s", err)
	}

	for _, pid := range dtP.ProjectIds {
		log.Debugf("Processing project %s", pid)

		prj, err := dTrackClient.Project.Get(ctx, pid)
		if err != nil {
			log.Infof("Failed to get project, Check projectID or API port or Hostname.")
			log.Fatalf("Failed to get project: %s", err)
		}
		log.Debugf("ID: %s, Name: %s, Version: %s", prj.UUID, prj.Name, prj.Version)

		bom, err := dTrackClient.BOM.ExportProject(ctx, pid, dtrack.BOMFormatJSON, dtrack.BOMVariantInventory)
		if err != nil {
			log.Fatalln("Failed to export project: %s", err)
		}

		fname := fmt.Sprintf("tmpfile-%s", pid)
		f, err := os.CreateTemp("", fname)
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()

		f.WriteString(bom)
		dtP.Input = append(dtP.Input, f.Name())
	}
}
