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

package edit

import (
	"errors"
	"time"
)

var (
	errNoConfiguration = errors.New("no configuration provided")
	errNotSupported    = errors.New("not supported")
	errInvalidInput    = errors.New("invalid input data")
)

// Subject constants for the --subject flag. Using constants prevents typos
// and makes refactoring safe across all edit implementations.
const (
	SubjectDocument            = "document"
	SubjectPrimaryComponent      = "primary-component"
	SubjectComponentNameVersion  = "component-name-version"
)

// ExternalIdentifierType constants for SPDX 3.0 external identifiers.
// These match the SPDX 3.0 JSON schema enum values (NOT SPDX 2.3 values).
const (
	ExtIDTypePurl  = "packageUrl"
	ExtIDTypeCpe23 = "cpe23"
	ExtIDTypeEmail = "email"
)

// ExternalRefType constants for SPDX 3.0 external references.
// The SPDX 3.0 spec has no dedicated "homepage" type; "other" is the
// recommended fallback for an organization's primary website URL.
const (
	ExtRefTypeOther = "other"
)

// RelationshipType constants for SPDX 3.0 relationships.
const (
	RelTypeHasConcludedLicense = "hasConcludedLicense"
)

func utcNowTime() string {
	location, _ := time.LoadLocation("UTC")
	locationTime := time.Now().In(location)
	return locationTime.Format(time.RFC3339)
}
