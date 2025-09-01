// Copyright 2025 Interlynk.io
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package edit

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/package-url/packageurl-go"
)

var supportedSubjects map[string]bool = map[string]bool{
	"document":               true,
	"primary-component":      true,
	"component-name-version": true,
}

type SearchParams struct {
	subject string
	name    string
	version string
	missing bool
	append  bool
}

type paramTuple struct {
	name  string
	value string
}

type configParams struct {
	ctx *context.Context

	inputFilePath  string
	outputFilePath string

	search SearchParams

	name        string
	version     string
	supplier    paramTuple
	authors     []paramTuple
	purl        string
	cpe         string
	licenses    []paramTuple
	hashes      []paramTuple
	tools       []paramTuple
	copyright   string
	lifecycles  []string
	description string
	repository  string
	typ         string

	timestamp bool
}

func (c *configParams) shouldTimeStamp() bool {
	return c.timestamp
}

func (c *configParams) shouldTyp() bool {
	return c.typ != ""
}

func (c *configParams) shouldRepository() bool {
	return c.repository != ""
}

func (c *configParams) shouldDescription() bool {
	return c.description != ""
}

func (c *configParams) shouldCopyRight() bool {
	return c.copyright != ""
}

func (c *configParams) shouldTools() bool {
	return len(c.tools) > 0
}

func (c *configParams) shouldHashes() bool {
	return len(c.hashes) > 0
}

func (c *configParams) shouldLicenses() bool {
	return len(c.licenses) > 0
}

func (c *configParams) shouldCpe() bool {
	return c.cpe != ""
}

func (c *configParams) shouldPurl() bool {
	return c.purl != ""
}

func (c *configParams) shouldAuthors() bool {
	return len(c.authors) > 0
}

func (c *configParams) shouldSupplier() bool {
	return c.supplier.value != ""
}

func (c *configParams) shouldVersion() bool {
	return c.version != ""
}

func (c *configParams) shouldName() bool {
	return c.name != ""
}

func (c *configParams) shouldOutput() bool {
	return c.outputFilePath != ""
}

func (c *configParams) shouldLifeCycle() bool {
	return len(c.lifecycles) > 0
}

func (c *configParams) onMissing() bool {
	return c.search.missing
}

func (c *configParams) onAppend() bool {
	return c.search.append
}

func (c *configParams) shouldSearch() bool {
	return c.search.subject == "component-name-version"
}

func (c *configParams) getFormattedAuthors() string {
	authors := []string{}
	for _, author := range c.authors {
		authors = append(authors, fmt.Sprintf("%s <%s>", author.name, author.value))
	}

	return strings.Join(authors, ",")
}

func convertToConfigParams(eParams *EditParams) (*configParams, error) {
	p := &configParams{}

	// log := logger.FromContext(*eParams.Ctx)

	p.ctx = eParams.Ctx

	if err := validatePath(eParams.Input); err != nil {
		return nil, err
	}

	p.inputFilePath = eParams.Input

	if eParams.Output != "" {
		p.outputFilePath = eParams.Output
	}

	p.search = SearchParams{}

	if eParams.Subject != "" {
		p.search.subject = eParams.Subject
	}

	p.search = SearchParams{}

	if eParams.Subject != "" && supportedSubjects[strings.ToLower(eParams.Subject)] {
		p.search.subject = strings.ToLower(eParams.Subject)
	} else {
		return nil, fmt.Errorf("unsupported subject %s", eParams.Subject)
	}

	if p.search.subject == "component-name-version" {
		name, version := parseInputFormat(eParams.Search)
		if name == "" || version == "" {
			return nil, fmt.Errorf("invalid component-name-version format both name and version must be provided")
		}
		p.search.name = name
		p.search.version = version
	}

	p.search.missing = eParams.Missing
	p.search.append = eParams.Append

	p.name = eParams.Name
	p.version = eParams.Version

	if eParams.Supplier != "" {
		name, email := parseInputFormat(eParams.Supplier)

		p.supplier = paramTuple{
			name:  name,
			value: email,
		}
	}

	for _, author := range eParams.Authors {
		name, email := parseInputFormat(author)
		p.authors = append(p.authors, paramTuple{
			name:  name,
			value: email,
		})
	}

	pkgPURL, err := packageurl.FromString(eParams.Purl)
	if err != nil {
		return nil, fmt.Errorf("provided PURL invalid")
	}

	p.purl = pkgPURL.String()
	p.cpe = eParams.Cpe

	for _, license := range eParams.Licenses {
		name, url := parseInputFormat(license)
		p.licenses = append(p.licenses, paramTuple{
			name:  name,
			value: url,
		})
	}

	for _, hash := range eParams.Hashes {
		algorithm, value := parseInputFormat(hash)
		p.hashes = append(p.hashes, paramTuple{
			name:  algorithm,
			value: value,
		})
	}

	for _, tool := range eParams.Tools {
		name, version := parseInputFormat(tool)
		p.tools = append(p.tools, paramTuple{
			name:  name,
			value: version,
		})
	}

	p.copyright = eParams.CopyRight
	p.lifecycles = eParams.Lifecycles
	p.description = eParams.Description
	p.repository = eParams.Repository
	p.typ = eParams.Type

	p.timestamp = eParams.Timestamp

	return p, nil
}

func parseInputFormat(s string) (name string, version string) {
	// Trim any leading/trailing whitespace
	s = strings.TrimSpace(s)

	// Regular expression to match the pattern
	re := regexp.MustCompile(`^(.+?)\s*(?:\(([^)]+)\))?$`)

	matches := re.FindStringSubmatch(s)
	if len(matches) > 1 {
		name = strings.TrimSpace(matches[1])
		if len(matches) > 2 {
			version = strings.TrimSpace(matches[2])
		}
	} else {
		name = s
	}

	return name, version
}

func validatePath(path string) error {
	stat, err := os.Stat(path)
	if err != nil {
		return err
	}

	if stat.IsDir() {
		return fmt.Errorf("path %s is a directory include only files", path)
	}

	return nil
}
