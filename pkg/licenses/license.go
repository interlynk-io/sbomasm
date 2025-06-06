// Copyright 2025 Interlynk.io
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

package licenses

import (
	"errors"
	"strings"

	go_spdx "github.com/github/go-spdx/v2/spdxexp"
)

type License interface {
	Name() string
	ShortID() string
	Deprecated() bool
	OsiApproved() bool
	FsfLibre() bool
	FreeAnyUse() bool
	Restrictive() bool
	Exception() bool
	Source() string
}

type meta struct {
	name        string
	short       string
	deprecated  bool
	osiApproved bool
	fsfLibre    bool
	freeAnyUse  bool
	restrictive bool
	exception   bool
	source      string
}

func (m meta) Name() string {
	return m.name
}

func (m meta) ShortID() string {
	return m.short
}

func (m meta) Deprecated() bool {
	return m.deprecated
}

func (m meta) OsiApproved() bool {
	return m.osiApproved
}

func (m meta) FsfLibre() bool {
	return m.fsfLibre
}

func (m meta) FreeAnyUse() bool {
	return m.freeAnyUse
}

func (m meta) Restrictive() bool {
	return m.restrictive
}

func (m meta) Exception() bool {
	return m.exception
}

func (m meta) Source() string {
	return m.source
}

func IsSpdxExpression(licenseKey string) bool {
	licenses, err := go_spdx.ExtractLicenses(licenseKey)
	if err != nil {
		return false
	}

	if len(licenses) <= 1 {
		return false
	}

	return true
}

func LookupSpdxLicense(licenseKey string) (License, error) {
	if licenseKey == "" {
		return nil, errors.New("license not found")
	}

	lowerKey := strings.ToLower(licenseKey)

	if lowerKey == "none" || lowerKey == "noassertion" {
		return nil, errors.New("license not found")
	}

	tLicKey := strings.TrimRight(licenseKey, "+")

	license, lok := licenseList[tLicKey]
	if lok {
		return license, nil
	}

	return nil, errors.New("license not found")
}

func LookupAdoutCodeLicense(licenseKey string) (License, error) {
	if licenseKey == "" {
		return nil, errors.New("license not found")
	}

	lowerKey := strings.ToLower(licenseKey)

	if lowerKey == "none" || lowerKey == "noassertion" {
		return nil, errors.New("license not found")
	}

	tLicKey := strings.TrimRight(licenseKey, "+")

	abouLicense, aok := LicenseListAboutCode[tLicKey]

	if aok {
		return abouLicense, nil
	}
	return nil, errors.New("license not found")
}

func LookupLicense(licenseKey string) (License, error) {
	spdxL, err := LookupSpdxLicense(licenseKey)
	abcL, err2 := LookupAdoutCodeLicense(licenseKey)

	if err != nil && err2 != nil {
		return nil, errors.New("license not found")
	}

	if err == nil {
		return spdxL, nil
	}

	if err2 == nil {
		return abcL, nil
	}

	return nil, errors.New("license not found")
}

func LookupExpression(expression string, customLicense []License) []License {
	customLookup := func(licenseKey string) (License, error) {
		if len(customLicense) == 0 {
			return nil, errors.New("license not found")
		}

		for _, l := range customLicense {
			if l.ShortID() == licenseKey {
				return l, nil
			}
		}
		return nil, errors.New("license not found")
	}

	if expression == "" || strings.ToLower(expression) == "none" || strings.ToLower(expression) == "noassertion" {
		return []License{}
	}

	licenses, err := go_spdx.ExtractLicenses(expression)
	if err != nil {
		return []License{CreateCustomLicense(expression, expression)}
	}

	ls := []License{}

	for _, l := range licenses {
		tLicKey := strings.TrimRight(l, "+")
		lic, err := LookupLicense(tLicKey)
		if err != nil {
			custLic, err2 := customLookup(tLicKey)
			if err2 != nil {
				ls = append(ls, CreateCustomLicense(tLicKey, tLicKey))
				continue
			}
			ls = append(ls, custLic)
		}

		if lic != nil {
			ls = append(ls, lic)
		}
	}

	return ls
}

func CreateCustomLicense(id, name string) License {
	return meta{
		name:        name,
		short:       id,
		deprecated:  false,
		osiApproved: false,
		fsfLibre:    false,
		freeAnyUse:  false,
		restrictive: false,
		exception:   false,
		source:      "custom",
	}
}
