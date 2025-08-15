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

package clearlydef

import (
	"context"
	"errors"
	"fmt"
	"strings"

	cydx "github.com/CycloneDX/cyclonedx-go"
	"github.com/interlynk-io/sbomasm/pkg/logger"
	"github.com/package-url/packageurl-go"
	"github.com/spdx/tools-golang/spdx"
)

type PKG_TYPE string

const (
	NPM   PKG_TYPE = "npm"
	GO    PKG_TYPE = "golang"
	PYPI  PKG_TYPE = "pypi"
	MAVEN PKG_TYPE = "maven"
	NUGET PKG_TYPE = "nuget"
	GEM   PKG_TYPE = "gem"
	DEB   PKG_TYPE = "deb"
)

type Coordinate struct {
	Type      string
	Provider  string
	Namespace string
	Name      string
	Revision  string
}

// Mapper maps component into coordinates for clearlydefined
func Mapper(ctx context.Context, components []interface{}) map[interface{}]Coordinate {
	log := logger.FromContext(ctx)
	log.Debug("mapping components to clearlydefined coordinates")

	coordinates := make(map[interface{}]Coordinate)

	for _, comp := range components {
		var coord Coordinate
		var err error
		var purls []string

		switch c := comp.(type) {
		case *spdx.Package:
			for _, ref := range c.PackageExternalReferences {
				if ref.RefType == "purl" {
					purls = append(purls, ref.Locator)
				}
			}

		case cydx.Component:
			if c.PackageURL != "" {
				purls = append(purls, c.PackageURL)
			}

		default:
			continue
		}

		// select first valid PURL
		for _, purl := range purls {
			coord, err = parsePURL(ctx, purl)
			if err == nil {
				break
			}
		}

		if err == nil {
			coordinates[comp] = coord
			if len(purls) > 1 {
				log.Debugf("multiple PURLs found for component: %s", comp)
			}
		}
	}
	log.Debugf("mapped %d components to coordinates", len(coordinates))

	return coordinates
}

// parsePURL converts a PURL to a ClearlyDefined coordinate
func parsePURL(ctx context.Context, purl string) (Coordinate, error) {
	log := logger.FromContext(ctx)
	log.Debugf("parsing PURL: %s", purl)

	if !strings.HasPrefix(purl, "pkg:") {
		log.Error("invalid PURL")
		return Coordinate{}, errors.New("invalid PURL")
	}

	// parse PURL directly using packageurl-go
	pkgPURL, err := packageurl.FromString(purl)
	if err != nil {
		log.Errorf("failed to parse PURL %s: %v", purl, err)
		return Coordinate{}, fmt.Errorf("failed to parse PURL: %w", err)
	}

	if pkgPURL.Type == "" || pkgPURL.Name == "" || pkgPURL.Version == "" {
		log.Errorf("invalid PURL %s: missing type, name, or version", purl)
		return Coordinate{}, errors.New("invalid PURL: missing type, name, or version")
	}

	log.Debugf("purl package_type=%s, namespace=%s, name=%s, version=%s", pkgPURL.Type, pkgPURL.Namespace, pkgPURL.Name, pkgPURL.Version)

	switch PKG_TYPE(pkgPURL.Type) {

	case NPM:
		return constructNPMCoordinate(ctx, pkgPURL)

	case GO:
		return constructGOCoordinate(ctx, pkgPURL)

	case PYPI:
		return constructPYPICoordinate(ctx, pkgPURL)

	case MAVEN:
		return constructMAVENCoordinate(ctx, pkgPURL)

	case NUGET:
		return constructNUGETCoordinate(ctx, pkgPURL)

	case GEM:
		return constructGEMCoordinate(ctx, pkgPURL)

	case DEB:
		return constructDEBCoordinate(ctx, pkgPURL)

	default:
		return Coordinate{}, errors.New("unsupported package type")
	}
}
