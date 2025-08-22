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
	"fmt"

	cydx "github.com/CycloneDX/cyclonedx-go"
	"github.com/guacsec/sw-id-core/coordinates"
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
func Mapper(ctx context.Context, components []interface{}) map[interface{}]coordinates.Coordinate {
	log := logger.FromContext(ctx)
	log.Debug("mapping components to clearlydefined coordinates")

	componentsToCoordinateMappings := make(map[interface{}]coordinates.Coordinate)
	totalComponents := len(components)
	missingPurl := 0
	invalidPurl := 0
	validPurl := 0

	for _, comp := range components {
		var coord *coordinates.Coordinate
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
		}

		if len(purls) == 0 {
			missingPurl++
			log.Debugf("no PURL found for component %T", comp)
			continue
		}

		coord, err = mapPURLToCoordinate(ctx, purls[0])
		if err != nil {
			invalidPurl++
			log.Debugf("%w", err)
			continue
		}
		validPurl++

		componentsToCoordinateMappings[comp] = *coord

	}
	fmt.Printf("Out of %d components, has %d missing PURLs, with %d invalid PURLs, and containing %d PURLs\n\n", totalComponents, missingPurl, invalidPurl, validPurl)
	log.Debugf("mapped %d components to coordinates", len(componentsToCoordinateMappings))

	return componentsToCoordinateMappings
}

// mapPURLToCoordinate converts a PURL to a ClearlyDefined coordinate
func mapPURLToCoordinate(ctx context.Context, purl string) (*coordinates.Coordinate, error) {
	log := logger.FromContext(ctx)
	// log.Debugf("initialized mapping PURL to coordinate: %s", purl)

	// if !strings.HasPrefix(purl, "pkg:") {
	// 	log.Error("invalid PURL")
	// 	return nil, errors.New("invalid PURL")
	// }

	// parse PURL directly using packageurl-go
	pkgPURL, err := packageurl.FromString(purl)
	if err != nil {
		log.Errorf("failed to parse PURL %s: %v", purl, err)
		return nil, fmt.Errorf("failed to parse PURL: %w", err)
	}

	coordinate, err := coordinates.ConvertPurlToCoordinate(pkgPURL.String())
	if err != nil {
		return nil, err
	}

	log.Debugf("mapped PURL %s to coordinate: %+v", purl, constructPathFromCoordinate(*coordinate))
	return coordinate, nil
}
