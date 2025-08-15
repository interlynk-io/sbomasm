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

	"github.com/interlynk-io/sbomasm/pkg/logger"
	"github.com/package-url/packageurl-go"
)

// constructNPMCoordinate constructs a ClearlyDefined coordinate from a NPM PURL
func constructNPMCoordinate(ctx context.Context, pkgPURL packageurl.PackageURL) (Coordinate, error) {
	log := logger.FromContext(ctx)
	log.Debugf("constructing NPM coordinate for purl: %s", pkgPURL)

	namespace := pkgPURL.Namespace
	if namespace != "" && !strings.HasPrefix(namespace, "@") {
		namespace = "@" + namespace // Ensure @scope format
	}
	return Coordinate{
		Type:      "npm",
		Provider:  "npmjs",
		Namespace: namespace,
		Name:      pkgPURL.Name,
		Revision:  pkgPURL.Version,
	}, nil
}

// constructGOCoordinate constructs a ClearlyDefined coordinate from a Go PURL
func constructGOCoordinate(ctx context.Context, pkgPURL packageurl.PackageURL) (Coordinate, error) {
	log := logger.FromContext(ctx)
	log.Debugf("constructing Go coordinate for purl: %s", pkgPURL)

	namespace, name := pkgPURL.Namespace, pkgPURL.Name

	if namespace == "" && strings.Contains(pkgPURL.Name, "/") {
		// Split name into namespace/name (e.g., github.com/sigstore/rekor)
		parts := strings.SplitN(pkgPURL.Name, "/", 2)
		if len(parts) == 2 {
			namespace = parts[0]
			name = parts[1]
		}
	}
	if namespace == "" {
		log.Warnf("no namespace in Go PURL: %s", pkgPURL)
	}

	encodedNamespace := url.PathEscape(namespace)
	log.Debugf("encoded namespace: %s, name: %s", encodedNamespace, name)

	return Coordinate{
		Type:      "go",
		Provider:  "golang",
		Namespace: encodedNamespace,
		Name:      name,
		Revision:  pkgPURL.Version,
	}, nil
}

// constructPYPICoordinate constructs a ClearlyDefined coordinate from a PyPI PURL
func constructPYPICoordinate(ctx context.Context, pkgPURL packageurl.PackageURL) (Coordinate, error) {
	log := logger.FromContext(ctx)
	log.Debugf("constructing PyPI coordinate for purl: %s", pkgPURL)

	return Coordinate{
		Type:      "pypi",
		Provider:  "pypi",
		Namespace: pkgPURL.Namespace, // Usually empty, but support if provided
		Name:      pkgPURL.Name,
		Revision:  pkgPURL.Version,
	}, nil
}

// constructMAVENCoordinate constructs a ClearlyDefined coordinate from a Maven PURL
func constructMAVENCoordinate(ctx context.Context, pkgPURL packageurl.PackageURL) (Coordinate, error) {
	log := logger.FromContext(ctx)
	log.Debugf("constructing Maven coordinate for purl: %s", pkgPURL)

	if pkgPURL.Namespace == "" {
		log.Warnf("invalid Maven PURL %s: missing namespace", pkgPURL)
		return Coordinate{}, errors.New("invalid Maven PURL: missing namespace")
	}

	return Coordinate{
		Type:      "maven",
		Provider:  "mavencentral",
		Namespace: pkgPURL.Namespace,
		Name:      pkgPURL.Name,
		Revision:  pkgPURL.Version,
	}, nil
}

// constructNUGETCoordinate constructs a ClearlyDefined coordinate from a NuGet PURL
func constructNUGETCoordinate(ctx context.Context, pkgPURL packageurl.PackageURL) (Coordinate, error) {
	log := logger.FromContext(ctx)
	log.Debugf("constructing NuGet coordinate for purl: %s", pkgPURL)

	return Coordinate{
		Type:      "nuget",
		Provider:  "nuget",
		Namespace: pkgPURL.Namespace, // Usually empty, but support if provided
		Name:      pkgPURL.Name,
		Revision:  pkgPURL.Version,
	}, nil
}

// constructGEMCoordinate constructs a ClearlyDefined coordinate from a Gem PURL
func constructGEMCoordinate(ctx context.Context, pkgPURL packageurl.PackageURL) (Coordinate, error) {
	log := logger.FromContext(ctx)
	log.Debugf("constructing Gem coordinate for purl: %s", pkgPURL)

	return Coordinate{
		Type:      "gem",
		Provider:  "rubygems",
		Namespace: pkgPURL.Namespace, // Usually empty, but support if provided
		Name:      pkgPURL.Name,
		Revision:  pkgPURL.Version,
	}, nil
}

// constructDEBCoordinate constructs a ClearlyDefined coordinate from a DEB PURL
func constructDEBCoordinate(ctx context.Context, pkgPURL packageurl.PackageURL) (Coordinate, error) {
	log := logger.FromContext(ctx)
	log.Debugf("constructing DEB coordinate for purl: %s", pkgPURL)

	return Coordinate{
		Type:      "deb",
		Provider:  "debian",
		Namespace: pkgPURL.Namespace, // Support debian or ubuntu
		Name:      pkgPURL.Name,
		Revision:  pkgPURL.Version,
	}, nil
}
