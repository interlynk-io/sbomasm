package edit

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/interlynk-io/sbomasm/pkg/detect"
	"github.com/interlynk-io/sbomasm/pkg/logger"
	"github.com/spdx/tools-golang/spdx"

	"github.com/samber/lo"
	spdx_json "github.com/spdx/tools-golang/json"
	spdx_rdf "github.com/spdx/tools-golang/rdf"
	"github.com/spdx/tools-golang/spdx/common"
	spdx_tv "github.com/spdx/tools-golang/tagvalue"
	spdx_yaml "github.com/spdx/tools-golang/yaml"
)

var spdx_hash_algos = map[string]spdx.ChecksumAlgorithm{
	"MD5":         spdx.MD5,
	"SHA-1":       spdx.SHA1,
	"SHA-256":     spdx.SHA256,
	"SHA-384":     spdx.SHA384,
	"SHA-512":     spdx.SHA512,
	"SHA3-256":    spdx.SHA256,
	"SHA3-384":    spdx.SHA384,
	"SHA3-512":    spdx.SHA512,
	"BLAKE2b-256": spdx.BLAKE2b_256,
	"BLAKE2b-384": spdx.BLAKE2b_384,
	"BLAKE2b-512": spdx.BLAKE2b_512,
	"BLAKE3":      spdx.BLAKE3,
}

var spdx_strings_to_types = map[string]string{
	"application":      "APPLICATION",
	"framework":        "FRAMEWORK",
	"library":          "LIBRARY",
	"container":        "CONTAINER",
	"operating-system": "OPERATING-SYSTEM",
	"device":           "DEVICE",
	"firmware":         "FIRMWARE",
	"source":           "SOURCE",
	"archive":          "ARCHIVE",
	"file":             "FILE",
	"install":          "INSTALL",
	"other":            "OTHER",
}

func spdxEdit(c *configParams) error {
	//log := logger.FromContext(*c.ctx)

	bom, err := loadSpdxSbom(*c.ctx, c.inputFilePath)
	if err != nil {
		return err
	}

	doc := NewSpdxEditDoc(bom, c)
	if doc == nil {
		return errors.New("failed to create spdx edit document")
	}

	doc.update()

	return writeSpdxSbom(doc.bom, c)
}

func loadSpdxSbom(ctx context.Context, path string) (*spdx.Document, error) {
	log := logger.FromContext(ctx)

	var d common.AnyDocument
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

	return d.(*spdx.Document), nil
}

func writeSpdxSbom(doc common.AnyDocument, m *configParams) error {
	var f io.Writer

	if m.outputFilePath == "" {
		f = os.Stdout
	} else {
		var err error
		f, err = os.Create(m.outputFilePath)
		if err != nil {
			return err
		}
	}

	inf, err := os.Open(m.inputFilePath)
	if err != nil {
		return err
	}
	defer inf.Close()

	_, format, err := detect.Detect(inf)
	if err != nil {
		return err
	}

	switch format {
	case detect.FileFormatJSON:
		var opt []spdx_json.WriteOption
		opt = append(opt, spdx_json.Indent(" "))      // to create multiline json
		opt = append(opt, spdx_json.EscapeHTML(true)) // to escape HTML characters
		spdx_json.Write(doc, f, opt...)
	case detect.FileFormatTagValue:
		spdx_tv.Write(doc, f)
	case detect.FileFormatYAML:
		spdx_yaml.Write(doc, f)
	case detect.FileFormatRDF:
		panic("write rdf format not supported")
	case detect.FileFormatXML:
		panic("write xml format not supported")
	}

	return nil
}

func spdxFindPkg(doc *spdx.Document, c *configParams, primaryPackage bool) (*spdx.Package, error) {
	pkgIDs := make(map[string]int)

	for index, pkg := range doc.Packages {
		pkgIDs[string(pkg.PackageSPDXIdentifier)] = index

		if primaryPackage == false {
			if pkg.PackageName == c.search.name && pkg.PackageVersion == c.search.version {
				return doc.Packages[index], nil
			}
		}
	}

	if primaryPackage {
		for _, r := range doc.Relationships {
			if strings.ToUpper(r.Relationship) == spdx.RelationshipDescribes {
				i, ok := pkgIDs[string(r.RefB.ElementRefID)]
				if ok {
					return doc.Packages[i], nil
				}
			}
		}
	}

	return nil, errors.New("package not found")
}

func spdxConstructLicenses(_ *spdx.Document, c *configParams) string {
	licenses := []string{}

	for _, l := range c.licenses {
		name := strings.ToLower(l.name)
		if name == "noassertion" || name == "none" {
			name = strings.ToUpper(l.name)
		} else {
			name = l.name
		}
		licenses = append(licenses, name)
	}

	return strings.Join(licenses, "OR")
}

func spdxConstructHashes(_ *spdx.Document, c *configParams) []spdx.Checksum {
	hashes := []spdx.Checksum{}

	for _, h := range c.hashes {
		hashes = append(hashes, spdx.Checksum{
			Algorithm: spdx.ChecksumAlgorithm(h.name),
			Value:     h.value,
		})
	}

	return hashes
}

func spdxConstructTools(_ *spdx.Document, c *configParams) []spdx.Creator {
	tools := []spdx.Creator{}
	uniqTools := make(map[string]bool)

	for _, tool := range c.tools {
		parts := []string{tool.name, tool.value}
		key := fmt.Sprintf("%s-%s", strings.ToLower(tool.name), strings.ToLower(tool.value))

		if _, ok := uniqTools[key]; !ok {
			tools = append(tools, spdx.Creator{
				CreatorType: "Tool",
				Creator:     strings.Join(lo.Compact(parts), "-"),
			})

			uniqTools[key] = true
		}
	}
	return tools
}

func spdxUniqueTools(a []spdx.Creator, b []spdx.Creator) []spdx.Creator {
	tools := a
	uniqTools := make(map[string]bool)

	for _, tool := range b {
		key := fmt.Sprintf("%s-%s", strings.ToLower(tool.CreatorType), strings.ToLower(tool.Creator))

		if _, ok := uniqTools[key]; !ok {
			tools = append(tools, tool)
			uniqTools[key] = true
		}
	}
	return tools
}
