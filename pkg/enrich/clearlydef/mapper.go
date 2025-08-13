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
	"net/url"
	"strings"

	cydx "github.com/CycloneDX/cyclonedx-go"
	"github.com/interlynk-io/sbomasm/pkg/logger"
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

// Map component into coordinate mapper for clearlydefined
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
			// error.HandleError(errors.New("unknown component type"), true)
			continue
		}

		// Select first valid PURL
		for _, purl := range purls {
			coord, err = parsePURL(ctx, purl)
			if err == nil {
				break
			}
		}

		if err == nil {
			coordinates[comp] = coord
			if len(purls) > 1 {
				// error.HandleError(fmt.Errorf("multiple PURLs for component %s; using %s", name, coord.ToPath()), true)
			}
		}
	}
	log.Debugf("mapped %d components to coordinates", len(coordinates))

	return coordinates
}

// parsePURL converts a PURL to a ClearlyDefined coordinate
func parsePURL(ctx context.Context, purl string) (Coordinate, error) {
	log := logger.FromContext(ctx)

	if !strings.HasPrefix(purl, "pkg:") {
		log.Error("invalid PURL")
		return Coordinate{}, errors.New("invalid PURL")
	}

	parts := strings.SplitN(purl[4:], "/", 2) // Remove "pkg:"
	if len(parts) < 2 {
		log.Error("invalid PURL format")
		return Coordinate{}, errors.New("invalid PURL format")
	}

	pkgType := parts[0]
	newPurl := parts[1]

	// Parse PURL to strip query parameters and fragments
	parsedURL, err := url.Parse(newPurl)
	if err != nil {
		log.Errorf("Failed to parse PURL %s: %v", purl, err)
		return Coordinate{}, errors.New("invalid PURL")
	}
	log.Debugf("Parsed PURL: %s", parsedURL)

	// Use path (removes ?query and #fragment)
	purlPath := parsedURL.Path
	if purlPath == "" {
		log.Error("invalid PURL: empty path")
		return Coordinate{}, errors.New("invalid PURL: empty path")
	}
	log.Debugf("PURL path: %s", purlPath)

	nameVersion := strings.SplitN(purlPath, "@", 2)
	if len(nameVersion) < 2 {
		log.Error("invalid PURL: missing version")
		return Coordinate{}, errors.New("invalid PURL: missing version")
	}
	name := nameVersion[0]
	version := nameVersion[1]

	log.Debugf("Parsing PURL: package_type=%s, name=%s, version=%s", pkgType, name, version)

	switch PKG_TYPE(pkgType) {

	case NPM:
		log.Debug("Parsing NPM PURL")
		return Coordinate{
			Type:      "npm",
			Provider:  "npmjs",
			Namespace: "",
			Name:      name,
			Revision:  version,
		}, nil

	case GO:
		log.Debug("Parsing Golang PURL")
		// e.g., pkg:go/github.com/quasilyte/regex/syntax@v0.0.0-20200419152657-af9db7f4a3ab
		pathParts := strings.SplitN(name, "/", 2)

		if len(pathParts) < 2 {
			log.Error("invalid Go PURL")
			return Coordinate{}, errors.New("invalid Go PURL")
		}

		namespace := pathParts[0]
		name = pathParts[1]
		encodedNamespace := url.PathEscape(namespace)

		log.Debugf("encoded namespace: %s, name: %s", encodedNamespace, name)

		return Coordinate{
			Type:      "go",
			Provider:  "golang",
			Namespace: encodedNamespace,
			Name:      name,
			Revision:  version,
		}, nil

	case PYPI:
		log.Debug("Parsing PyPI PURL")
		return Coordinate{
			Type:      "pypi",
			Provider:  "pypi",
			Namespace: "",
			Name:      name,
			Revision:  version,
		}, nil

	case MAVEN:
		log.Debug("Parsing Maven PURL")
		parts := strings.SplitN(name, "/", 2)
		if len(parts) < 2 {
			return Coordinate{}, errors.New("invalid Maven PURL")
		}
		return Coordinate{
			Type:      "maven",
			Provider:  "mavencentral",
			Namespace: parts[0],
			Name:      parts[1],
			Revision:  version,
		}, nil

	case NUGET:
		log.Debug("Parsing NuGet PURL")
		return Coordinate{
			Type:      "nuget",
			Provider:  "nuget",
			Namespace: "",
			Name:      name,
			Revision:  version,
		}, nil

	case GEM:
		log.Debug("Parsing Gem PURL")
		return Coordinate{
			Type:      "gem",
			Provider:  "rubygems",
			Namespace: "",
			Name:      name,
			Revision:  version,
		}, nil

	case DEB:
		log.Debug("Parsing DEB PURL")
		return Coordinate{
			Type:      "deb",
			Provider:  "debian",
			Namespace: "",
			Name:      name,
			Revision:  version,
		}, nil

	default:
		return Coordinate{}, errors.New("unsupported package type")
	}
}
