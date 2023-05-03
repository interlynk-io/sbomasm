// Copyright 2023 Interlynk.io
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
	"fmt"
	"net/url"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/interlynk-io/sbomasm/pkg/detect"
	"github.com/interlynk-io/sbomasm/pkg/logger"
	"github.com/mitchellh/copystructure"
	spdx_json "github.com/spdx/tools-golang/json"
	spdx_rdf "github.com/spdx/tools-golang/rdf"
	"github.com/spdx/tools-golang/spdx"
	"github.com/spdx/tools-golang/spdx/v2/v2_3"
	spdx_tv "github.com/spdx/tools-golang/tagvalue"
	spdx_yaml "github.com/spdx/tools-golang/yaml"
)

func loadBom(ctx context.Context, path string) (*v2_3.Document, error) {
	log := logger.FromContext(ctx)

	var d *v2_3.Document
	var err error

	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	spec, format, err := detect.Detect(f)
	if err != nil {
		return nil, err
	}

	log.Debugf("loading bom:%s spec:%s format:%s", path, spec, format)

	switch format {
	case detect.FileFormatJSON:
		d, err = spdx_json.Read(f)
	case detect.FileFormatTagValue:
		d, err = spdx_tv.Read(f)
	case detect.FileFormatYAML:
		d, err = spdx_yaml.Read(f)
	case detect.FileFormatRDF:
		d, err = spdx_rdf.Read(f)
	default:
		panic("unsupported spdx format")

	}

	if err != nil {
		return nil, err
	}

	return d, nil
}

func utcNowTime() string {
	location, _ := time.LoadLocation("UTC")
	locationTime := time.Now().In(location)
	return locationTime.Format("2006-01-02T15:04:05Z")
}

func cloneComp(c *spdx.Package) (*spdx.Package, error) {
	compCopy, err := copystructure.Copy(c)
	if err != nil {
		return nil, err
	}

	return compCopy.(*spdx.Package), nil
}

func composeNamespace(docName string) string {
	uuid := uuid.New().String()
	path := fmt.Sprintf("%s/%s-%s", "spdxdocs", docName, uuid)
	url := url.URL{
		Scheme: "https",
		Host:   "spdx.org",
		Path:   path,
	}
	return url.String()
}
