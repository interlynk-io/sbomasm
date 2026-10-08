// Copyright 2026 Interlynk.io
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
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	cydx "github.com/CycloneDX/cyclonedx-go"
	spdx3 "github.com/interlynk-io/spdx-zen/model/v3.0.1"
	"github.com/interlynk-io/spdx-zen/parse"
	spdx_json "github.com/spdx/tools-golang/json"
	"github.com/spdx/tools-golang/spdx"
)

// ── Parse Helpers ──

func parseSpdx3FromBytes(t *testing.T, data []byte) *parse.Document {
	t.Helper()
	doc, err := parse.NewReader().FromReader(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("failed to parse SPDX 3.0 from bytes: %v", err)
	}
	// Sync: the parser stores CreationInfo in doc.CreationInfo (shared blank
	// node), but the edit code mutates doc.SpdxDocument.CreationInfo. Copy
	// the parsed data over so document-level mutations work.
	if doc.CreationInfo != nil && doc.SpdxDocument != nil {
		doc.SpdxDocument.CreationInfo = *doc.CreationInfo
	}
	return doc
}

func parseSpdx23FromBytes(t *testing.T, data []byte) *spdx.Document {
	t.Helper()
	doc, err := spdx_json.Read(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("failed to parse SPDX 2.3 from bytes: %v", err)
	}
	return doc
}

func parseCdxFromBytes(t *testing.T, data []byte) *cydx.BOM {
	t.Helper()
	bom := new(cydx.BOM)
	decoder := cydx.NewBOMDecoder(bytes.NewReader(data), cydx.BOMFileFormatJSON)
	if err := decoder.Decode(bom); err != nil {
		t.Fatalf("failed to parse CycloneDX from bytes: %v", err)
	}
	return bom
}

// ── Config Helper ──

func newConfig(t *testing.T, subject string, mode string, fields ...func(*configParams)) *configParams {
	t.Helper()
	ctx := context.Background()
	cfg := &configParams{
		ctx: &ctx,
		search: SearchParams{
			subject: strings.ToLower(subject),
		},
	}

	switch mode {
	case "append":
		cfg.search.append = true
	case "missing":
		cfg.search.missing = true
	case "overwrite":
		// default
	default:
		t.Fatalf("unsupported mode: %s (use overwrite, append, or missing)", mode)
	}

	for _, f := range fields {
		f(cfg)
	}
	return cfg
}

// withAuthor appends an author tuple "Name (email)".
func withAuthor(author string) func(*configParams) {
	return func(c *configParams) {
		name, email := parseInputFormat(author)
		c.authors = append(c.authors, paramTuple{name: name, value: email})
	}
}

// withSupplier sets a supplier tuple "Name (url_or_email)".
func withSupplier(supplier string) func(*configParams) {
	return func(c *configParams) {
		name, val := parseInputFormat(supplier)
		c.supplier = paramTuple{name: name, value: val}
	}
}

// withTool appends a tool tuple "Name (version)".
func withTool(tool string) func(*configParams) {
	return func(c *configParams) {
		name, version := parseInputFormat(tool)
		c.tools = append(c.tools, paramTuple{name: name, value: version})
	}
}

// withLicense appends a license tuple "ID (url)".
func withLicense(license string) func(*configParams) {
	return func(c *configParams) {
		name, url := parseInputFormat(license)
		c.licenses = append(c.licenses, paramTuple{name: name, value: url})
	}
}

// withHash appends a hash tuple "Algorithm (value)".
func withHash(hash string) func(*configParams) {
	return func(c *configParams) {
		alg, val := parseInputFormat(hash)
		c.hashes = append(c.hashes, paramTuple{name: alg, value: val})
	}
}

// withName sets the component name.
func withName(name string) func(*configParams) {
	return func(c *configParams) { c.name = name }
}

// withVersion sets the component version.
func withVersion(version string) func(*configParams) {
	return func(c *configParams) { c.version = version }
}

// withDescription sets the description.
func withDescription(desc string) func(*configParams) {
	return func(c *configParams) { c.description = desc }
}

// withCopyright sets the copyright text.
func withCopyright(text string) func(*configParams) {
	return func(c *configParams) { c.copyright = text }
}

// withRepository sets the repository URL.
func withRepository(url string) func(*configParams) {
	return func(c *configParams) { c.repository = url }
}

// withType sets the component type.
func withType(typ string) func(*configParams) {
	return func(c *configParams) { c.typ = typ }
}

// withPurl sets the package URL.
func withPurl(purl string) func(*configParams) {
	return func(c *configParams) { c.purl = purl }
}

// withCpe sets the CPE.
func withCpe(cpe string) func(*configParams) {
	return func(c *configParams) { c.cpe = cpe }
}

// withLifecycle appends a lifecycle phase.
func withLifecycle(phase string) func(*configParams) {
	return func(c *configParams) { c.lifecycles = append(c.lifecycles, phase) }
}

// withTimestamp enables timestamp.
func withTimestamp() func(*configParams) {
	return func(c *configParams) { c.timestamp = true }
}

// withSearch sets component-name-version search params.
func withSearch(name, version string) func(*configParams) {
	return func(c *configParams) {
		c.search.subject = SubjectComponentNameVersion
		c.search.name = name
		c.search.version = version
	}
}

// ── Stderr Capture Helper ──

// captureStderr runs fn while capturing anything written to os.Stderr,
// then returns the captured text.
func captureStderr(fn func()) string {
	oldStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	fn()

	_ = w.Close()
	os.Stderr = oldStderr

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	return buf.String()
}

// ── SPDX 3.0 Assertion Helpers ──

func assertAgentInCreatedBy(t *testing.T, ci *spdx3.CreationInfo, spdxID string) {
	t.Helper()
	for _, a := range ci.CreatedBy {
		if a.SpdxID == spdxID {
			return
		}
	}
	t.Fatalf("expected SpdxID %q in CreatedBy, got %v", spdxID, ci.CreatedBy)
}

func assertHasExternalRef(t *testing.T, element *spdx3.Element, refType spdx3.ExternalRefType, locator string) {
	t.Helper()
	for _, ref := range element.ExternalRef {
		if ref.ExternalRefType == refType {
			for _, l := range ref.Locator {
				if l == locator {
					return
				}
			}
		}
	}
	t.Fatalf("expected ExternalRef{type:%s, locator:%q} not found", refType, locator)
}

func assertHasExternalIdentifier(t *testing.T, element *spdx3.Element, idType spdx3.ExternalIdentifierType, value string) {
	t.Helper()
	for _, id := range element.ExternalIdentifier {
		if id.ExternalIdentifierType == idType && id.Identifier == value {
			return
		}
	}
	t.Fatalf("expected ExternalIdentifier{type:%s, identifier:%q} not found", idType, value)
}

func assertHasHash(t *testing.T, element *spdx3.Element, alg string, value string) {
	t.Helper()
	for _, v := range element.VerifiedUsing {
		switch h := v.(type) {
		case spdx3.Hash:
			if string(h.Algorithm) == alg && h.HashValue == value {
				return
			}
		case *spdx3.Hash:
			if string(h.Algorithm) == alg && h.HashValue == value {
				return
			}
		}
	}
	t.Fatalf("expected Hash{algorithm:%s, value:%q} not found in verifiedUsing", alg, value)
}

func assertLicenseExpression(t *testing.T, doc *parse.Document, exprText string) {
	t.Helper()
	for _, le := range doc.LicenseExpressions {
		if le.LicenseExpression == exprText {
			return
		}
	}
	t.Fatalf("expected LicenseExpression %q not found in document", exprText)
}

func assertWarningContains(t *testing.T, stderr string, field string) {
	t.Helper()
	expected := fmt.Sprintf("--append is not applicable to --%s", field)
	if !bytes.Contains([]byte(stderr), []byte(expected)) {
		t.Fatalf("expected stderr to contain %q, got:\n%s", expected, stderr)
	}
}
