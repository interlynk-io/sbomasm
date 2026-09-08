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

package spdx

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/interlynk-io/sbomasm/v2/pkg/logger"
	"github.com/interlynk-io/sbomasm/v2/pkg/sbom"
	"github.com/mitchellh/copystructure"
	"github.com/pingcap/log"
	"github.com/samber/lo"
	spdx_json "github.com/spdx/tools-golang/json"
	spdx_rdf "github.com/spdx/tools-golang/rdf"
	"github.com/spdx/tools-golang/spdx"
	"github.com/spdx/tools-golang/spdx/v2/common"
	"github.com/spdx/tools-golang/spdx/v2/v2_3"
	spdx_tv "github.com/spdx/tools-golang/tagvalue"
	spdx_yaml "github.com/spdx/tools-golang/yaml"
	"sigs.k8s.io/release-utils/version"
)

const NOA = "NOASSERTION"

var specVersionMap = map[string]string{
	"2.3": v2_3.Version,
}

func validSpecVersion(specVersion string) bool {
	_, ok := specVersionMap[specVersion]
	return ok
}

func loadBom(ctx context.Context, path string) (*v2_3.Document, error) {
	log := logger.FromContext(ctx)

	var d *v2_3.Document
	var err error

	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	spec, format, err := sbom.Detect(f)
	if err != nil {
		return nil, err
	}

	log.Debugf("loading bom:%s spec:%s format:%s", path, spec, format)

	switch format {
	case sbom.FileFormatJSON:
		d, err = spdx_json.Read(f)
	case sbom.FileFormatTagValue:
		d, err = spdx_tv.Read(f)
	case sbom.FileFormatYAML:
		d, err = spdx_yaml.Read(f)
	case sbom.FileFormatRDF:
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
	return time.Now().UTC().Format(time.RFC3339)
}

func clonePkg(c *spdx.Package) (*spdx.Package, error) {
	compCopy, err := copystructure.Copy(c)
	if err != nil {
		return nil, err
	}

	return compCopy.(*spdx.Package), nil
}

func cloneFile(c *spdx.File) (*spdx.File, error) {
	fileCopy, err := copystructure.Copy(c)
	if err != nil {
		return nil, err
	}

	return fileCopy.(*spdx.File), nil
}

func cloneRelationship(c *spdx.Relationship) (*spdx.Relationship, error) {
	relCopy, err := copystructure.Copy(c)
	if err != nil {
		return nil, err
	}

	return relCopy.(*spdx.Relationship), nil
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

// If we are merging documents, which are included as external references, we should
// remove those. As they are no longer external references.
func externalDocumentRefs(docs []*v2_3.Document) []v2_3.ExternalDocumentRef {
	currentDocNamespaces := lo.Map(docs, func(doc *v2_3.Document, _ int) string {
		return doc.DocumentNamespace
	})

	refs := []v2_3.ExternalDocumentRef{}

	for _, doc := range docs {
		for _, ref := range doc.ExternalDocumentReferences {
			if !lo.Contains(currentDocNamespaces, ref.URI) {
				refs = append(refs, ref)
			}
		}
	}

	return refs
}

func getAllCreators(docs []*v2_3.Document, authors []Author) []common.Creator {
	var creators []common.Creator
	uniqCreator := make(map[string]common.Creator)

	for _, doc := range docs {
		if doc.CreationInfo != nil {
			for _, c := range doc.CreationInfo.Creators {
				if c.Creator == "" {
					continue
				}
				if _, ok := uniqCreator[c.Creator]; !ok {
					uniqCreator[c.Creator] = c
					creators = append(creators, c)
				}
			}
		}
	}

	for _, author := range authors {
		// Skip authors with empty names (e.g., sanitized [OPTIONAL] values)
		if author.Name == "" {
			continue
		}

		authorCreator := ""
		if author.Email == "" {
			authorCreator = author.Name
		} else {
			authorCreator = fmt.Sprintf("%s (%s)", author.Name, author.Email)
		}
		creators = append(creators, common.Creator{
			CreatorType: "Person",
			Creator:     authorCreator,
		})
	}

	sbomAsmCreator := common.Creator{
		CreatorType: "Tool",
		Creator:     fmt.Sprintf("%s-%s", "sbomasm", version.GetVersionInfo().GitVersion),
	}

	creators = append(creators, sbomAsmCreator)
	return creators
}

func getCreatorComments(docs []*v2_3.Document) string {
	comments := lo.Uniq(lo.Map(docs, func(bom *spdx.Document, _ int) string {
		if bom.CreationInfo != nil {
			return bom.CreationInfo.CreatorComment
		}
		return ""
	}))

	docNames := lo.Uniq(lo.Map(docs, func(doc *v2_3.Document, _ int) string {
		return doc.DocumentName
	}))

	sbomasmComment := fmt.Sprintf("Generated by sbomasm (%s) using %s",
		version.GetVersionInfo().GitVersion, strings.Join(docNames, ", "))

	finalComments := append([]string{sbomasmComment}, comments...)

	return strings.Join(finalComments, "\n")
}

func getLicenseListVersion(docs []*v2_3.Document) string {
	versions := lo.Uniq(lo.Map(docs, func(bom *spdx.Document, _ int) string {
		if bom.CreationInfo != nil && bom.CreationInfo.LicenseListVersion != "" {
			return bom.CreationInfo.LicenseListVersion
		}
		return ""
	}))

	if len(versions) == 0 {
		return ""
	}

	sort.Slice(versions, func(i, j int) bool {
		return compareVersions(versions[i], versions[j])
	})

	return versions[len(versions)-1]
}

func compareVersions(a, b string) bool {
	aParts := strings.Split(a, ".")
	bParts := strings.Split(b, ".")

	for i := 0; i < len(aParts) && i < len(bParts); i++ {
		aNum, _ := strconv.Atoi(aParts[i])
		bNum, _ := strconv.Atoi(bParts[i])

		if aNum != bNum {
			return aNum < bNum
		}
	}

	return len(aParts) < len(bParts)
}

func genOtherLicenses(docs []*v2_3.Document) []*v2_3.OtherLicense {
	customLicenses := lo.FlatMap(docs, func(doc *spdx.Document, _ int) []*spdx.OtherLicense {
		return doc.OtherLicenses
	})

	if len(customLicenses) == 0 {
		return nil
	}

	return lo.UniqBy(customLicenses, func(license *spdx.OtherLicense) string {
		// A license would be unique if the identifier is the same & content
		contentList := []string{license.LicenseIdentifier, license.ExtractedText}
		jointContent := strings.Join(contentList, "")

		checksum := sha256.Sum256([]byte(jointContent))
		return fmt.Sprintf("%x", checksum)
	})
}

func genSpdxDocumentMetadata(ms *merge) (*v2_3.Document, error) {
	if ms == nil {
		return nil, fmt.Errorf("settings is required")
	}

	doc := v2_3.Document{}

	doc.SPDXVersion = v2_3.Version
	doc.DataLicense = v2_3.DataLicense
	doc.SPDXIdentifier = common.ElementID("DOCUMENT")
	doc.DocumentName = ms.settings.App.Name
	doc.DocumentNamespace = composeNamespace(ms.settings.App.Name)

	return &doc, nil
}

func genCreationInfo(ms *merge) (*v2_3.CreationInfo, error) {
	ci := v2_3.CreationInfo{}

	// set UTC time
	ci.Created = utcNowTime()
	ci.CreatorComment = getCreatorComments(ms.in)
	lVersions := getLicenseListVersion(ms.in)
	if lVersions != "" {
		ci.LicenseListVersion = lVersions
	}
	creators := getAllCreators(ms.in, ms.settings.App.Authors)
	ci.Creators = append(ci.Creators, creators...)
	return &ci, nil
}

func genPrimaryPackage(ms *merge) (*v2_3.Package, error) {
	pkg := v2_3.Package{}

	pkg.PackageName = ms.settings.App.Name
	pkg.PackageVersion = ms.settings.App.Version
	pkg.PackageDescription = ms.settings.App.Description
	pkg.PackageSPDXIdentifier = common.ElementID(fmt.Sprintf("RootPackage-%s", ms.rootPackageID))
	pkg.PackageDownloadLocation = NOA
	// This is set to true since we are analyzing the merged sboms files
	pkg.FilesAnalyzed = true

	// Add Supplier
	if ms.settings.App.Supplier.Name != "" {
		pkg.PackageSupplier = &common.Supplier{}
		pkg.PackageSupplier.SupplierType = "Organization"

		if ms.settings.App.Supplier.Email == "" {
			pkg.PackageSupplier.Supplier = ms.settings.App.Supplier.Name
		} else {
			pkg.PackageSupplier.Supplier = fmt.Sprintf("%s (%s)", ms.settings.App.Supplier.Name, ms.settings.App.Supplier.Email)
		}
	}

	// Add checksums if provided.
	if len(ms.settings.App.Checksums) > 0 {
		pkg.PackageChecksums = []common.Checksum{}
		for _, c := range ms.settings.App.Checksums {
			if len(c.Value) == 0 {
				continue
			}
			pkg.PackageChecksums = append(pkg.PackageChecksums, common.Checksum{
				Algorithm: spdx_hash_algos[c.Algorithm],
				Value:     c.Value,
			})
		}
	}

	if ms.settings.App.License.Id != "" {
		pkg.PackageLicenseConcluded = ms.settings.App.License.Id
	} else if ms.settings.App.License.Expression != "" {
		pkg.PackageLicenseConcluded = ms.settings.App.License.Expression
	} else {
		pkg.PackageLicenseConcluded = NOA
	}

	if ms.settings.App.Copyright != "" {
		pkg.PackageCopyrightText = ms.settings.App.Copyright
	} else {
		pkg.PackageCopyrightText = NOA
	}

	if _, ok := spdx_strings_to_types[ms.settings.App.PrimaryPurpose]; ok {
		pkg.PrimaryPackagePurpose = spdx_strings_to_types[ms.settings.App.PrimaryPurpose]
	} else {
		log.Warn(fmt.Sprintf("PrimaryPurpose %s is not a valid SPDX Package Purpose", ms.settings.App.PrimaryPurpose))
	}
	if ms.settings.App.Purl != "" {
		purl := spdx.PackageExternalReference{
			Category: common.CategoryPackageManager,
			RefType:  common.TypePackageManagerPURL,
			Locator:  ms.settings.App.Purl,
		}
		pkg.PackageExternalReferences = append(pkg.PackageExternalReferences, &purl)
	}

	if ms.settings.App.CPE != "" {
		cpe := spdx.PackageExternalReference{
			Category: common.CategorySecurity,
			RefType:  common.TypeSecurityCPE23Type,
			Locator:  ms.settings.App.CPE,
		}
		pkg.PackageExternalReferences = append(pkg.PackageExternalReferences, &cpe)
	}
	return &pkg, nil
}

func createLookupKey(docName, spdxId string) string {
	return fmt.Sprintf("%s:%s", docName, spdxId)
}

// rootPackageInfo holds the namespace and SPDX ID of the primary package
// from the primary SBOM, so genPackageList can assign it the root package ID.
type rootPackageInfo struct {
	DocNamespace string
	SPDXID       string
}

func findPrimaryAndSecondarySBOMIndices(docCount int) (int, []int) {
	primaryIdx := 0
	var secondaryIdxs []int
	for i := 1; i < docCount; i++ {
		secondaryIdxs = append(secondaryIdxs, i)
	}
	return primaryIdx, secondaryIdxs
}

// getDescribedPkgID returns the SPDX ElementID of the package that is the
// target of the DESCRIBES relationship in the given document.
func getDescribedPkgID(doc *v2_3.Document) common.ElementID {
	for _, rel := range doc.Relationships {
		if rel.Relationship == common.TypeRelationshipDescribe && rel.RefB.ElementRefID != "" {
			return rel.RefB.ElementRefID
		}
	}
	return ""
}

// extractPrimaryPackage finds and clones the package that is described by
// the primary SBOM's DESCRIBES relationship.
func extractPrimaryPackage(doc *v2_3.Document) (*v2_3.Package, error) {
	primaryPkgID := getDescribedPkgID(doc)
	if primaryPkgID == "" {
		return nil, fmt.Errorf("primary SBOM has no DESCRIBES relationship")
	}

	for _, pkg := range doc.Packages {
		if strings.EqualFold(string(pkg.PackageSPDXIdentifier), string(primaryPkgID)) {
			clone, err := clonePkg(pkg)
			if err != nil {
				return nil, err
			}
			return clone, nil
		}
	}

	return nil, fmt.Errorf("primary package %s not found in primary SBOM", primaryPkgID)
}

// initOutDocFromPrimarySBOM initializes the output document metadata from the
// primary SBOM, preserving its identity (document name and namespace).
func initOutDocFromPrimarySBOM(m *merge, primaryDoc *v2_3.Document) (*v2_3.Document, error) {
	doc := v2_3.Document{}

	doc.SPDXVersion = v2_3.Version
	doc.SPDXIdentifier = common.ElementID("DOCUMENT")
	doc.DocumentName = primaryDoc.DocumentName
	doc.DocumentNamespace = primaryDoc.DocumentNamespace

	// Handle document license override
	docLicense := m.settings.Assemble.DocLicense
	if docLicense != "" {
		if strings.EqualFold(docLicense, "none") {
			doc.DataLicense = ""
		} else {
			doc.DataLicense = docLicense
		}
	} else if primaryDoc.DataLicense != "" {
		doc.DataLicense = primaryDoc.DataLicense
	} else {
		doc.DataLicense = v2_3.DataLicense
	}

	return &doc, nil
}

// initCreationInfoFromPrimarySBOM initializes creation info preserving the primary
// SBOM's creators, adding sbomasm and any CLI authors, and updating the timestamp.
func initCreationInfoFromPrimarySBOM(m *merge, primaryDoc *v2_3.Document) (*v2_3.CreationInfo, error) {
	ci := v2_3.CreationInfo{}

	// Update timestamp to reflect modification
	ci.Created = utcNowTime()

	// Generate comment referencing all merged documents
	docNames := lo.Map(m.in, func(doc *v2_3.Document, _ int) string {
		return doc.DocumentName
	})

	sbomasmComment := fmt.Sprintf("Generated by sbomasm (%s) using %s",
		version.GetVersionInfo().GitVersion, strings.Join(docNames, ", "))

	var comments []string
	if primaryDoc.CreationInfo != nil && primaryDoc.CreationInfo.CreatorComment != "" {
		comments = append(comments, primaryDoc.CreationInfo.CreatorComment)
	}

	comments = append(comments, sbomasmComment)
	ci.CreatorComment = strings.Join(comments, "\n")

	// Preserve primary's creators
	var creators []common.Creator
	if primaryDoc.CreationInfo != nil {
		for _, c := range primaryDoc.CreationInfo.Creators {
			if c.Creator == "" {
				continue
			}
			creators = append(creators, c)
		}
	}

	// Add sbomasm tool
	sbomAsmCreator := common.Creator{
		CreatorType: "Tool",
		Creator:     fmt.Sprintf("%s-%s", "sbomasm", version.GetVersionInfo().GitVersion),
	}
	creators = append(creators, sbomAsmCreator)

	// Deduplicate creators by Creator string
	uniqCreator := make(map[string]bool)
	var finalCreators []common.Creator
	for _, c := range creators {
		if _, ok := uniqCreator[c.Creator]; ok {
			continue
		}
		uniqCreator[c.Creator] = true
		finalCreators = append(finalCreators, c)
	}
	ci.Creators = finalCreators

	return &ci, nil
}

// getSecondaryDescribedPkgs returns the described packages from secondary SBOMs only.
func getSecondaryDescribedPkgs(docs []*v2_3.Document, secondaryIdxs []int) []string {
	pkgs := []string{}
	for _, idx := range secondaryIdxs {
		doc := docs[idx]
		for _, rel := range doc.Relationships {
			if rel.Relationship == common.TypeRelationshipDescribe && rel.RefB.ElementRefID != "" {
				pkgs = append(pkgs, createLookupKey(doc.DocumentNamespace, string(rel.RefB.ElementRefID)))
			}
		}
	}
	return pkgs
}

func genPackageList(ms *merge, rootPkgInfo *rootPackageInfo) ([]*v2_3.Package, map[string]string, error) {
	var pkgs []*v2_3.Package
	mapper := make(map[string]string)
	seen := make(map[string]string)

	for _, doc := range ms.in {
		for _, pkg := range doc.Packages {
			key := fmt.Sprintf("%s-%s", strings.ToLower(pkg.PackageName), strings.ToLower(pkg.PackageVersion))

			// Check if this is the root package from the primary SBOM
			isRootPkg := rootPkgInfo != nil &&
				doc.DocumentNamespace == rootPkgInfo.DocNamespace &&
				string(pkg.PackageSPDXIdentifier) == rootPkgInfo.SPDXID

			// if already seen, map the old SPDXID to the new SPDXID
			if newID, exists := seen[key]; exists {
				oldSpdxId := createLookupKey(doc.DocumentNamespace, string(pkg.PackageSPDXIdentifier))
				mapper[oldSpdxId] = newID
				continue
			}

			clone, err := clonePkg(pkg)
			if err != nil {
				return nil, nil, err
			}

			var newSpdxId common.ElementID
			if isRootPkg {
				newSpdxId = common.ElementID(fmt.Sprintf("RootPackage-%s", ms.rootPackageID))
			} else {
				newSpdxId = common.ElementID(fmt.Sprintf("Package-%s", uuid.New().String()))
			}

			oldSpdxId := createLookupKey(doc.DocumentNamespace, string(pkg.PackageSPDXIdentifier))

			mapper[oldSpdxId] = string(newSpdxId)
			seen[key] = string(newSpdxId)
			clone.PackageSPDXIdentifier = newSpdxId

			if !clone.FilesAnalyzed {
				clone.PackageVerificationCode = nil
			}
			if clone.PackageVerificationCode != nil && clone.PackageVerificationCode.Value == "" {
				clone.PackageVerificationCode = nil
				clone.FilesAnalyzed = false
			}
			clone.Files = nil

			pkgs = append(pkgs, clone)
		}
	}

	return pkgs, mapper, nil
}

func genFileList(ms *merge) ([]*v2_3.File, map[string]string, error) {
	var files []*v2_3.File
	mapper := make(map[string]string)

	for _, doc := range ms.in {
		// Add the files from the document
		for _, file := range doc.Files {
			// Clone the file
			clone, err := cloneFile(file)
			if err != nil {
				return nil, nil, err
			}

			newSpdxId := common.ElementID(fmt.Sprintf("File-%s", uuid.New().String()))
			oldSpdxId := createLookupKey(doc.DocumentNamespace, string(file.FileSPDXIdentifier))

			mapper[oldSpdxId] = string(newSpdxId)
			clone.FileSPDXIdentifier = newSpdxId

			// Add the file to the list
			files = append(files, clone)
		}

		// Add the files from the packages
		for _, pkg := range doc.Packages {
			for _, file := range pkg.Files {
				// Clone the file
				clone, err := cloneFile(file)
				if err != nil {
					return nil, nil, err
				}

				newSpdxId := common.ElementID(fmt.Sprintf("File-%s", uuid.New().String()))
				oldSpdxId := createLookupKey(doc.DocumentNamespace, string(file.FileSPDXIdentifier))

				mapper[oldSpdxId] = string(newSpdxId)
				clone.FileSPDXIdentifier = newSpdxId

				// Add the file to the list
				files = append(files, clone)
			}
		}
	}

	return files, mapper, nil
}

func genRelationships(ms *merge, pkgMapper map[string]string, fileMapper map[string]string) ([]*v2_3.Relationship, error) {
	var relationships []*v2_3.Relationship

	docNames := lo.Map(ms.in, func(doc *v2_3.Document, _ int) string {
		return doc.DocumentName
	})

	for _, doc := range ms.in {
		for _, rel := range doc.Relationships {
			if rel.Relationship == common.TypeRelationshipDescribe {
				continue
			}

			// Clone the relationship
			clone, err := cloneRelationship(rel)
			if err != nil {
				return nil, err
			}

			// if the relationship has a DocumentRef defined, and the
			// document is part of the merge set, we should null it out.
			if rel.RefA.DocumentRefID != "" {
				if lo.Contains(docNames, string(rel.RefA.DocumentRefID)) {
					clone.RefA.DocumentRefID = ""
				} else {
					log.Warn(fmt.Sprintf("RefA: Could not find document name %s in the merge set", rel.RefA.DocumentRefID))
				}
			}

			if rel.RefB.DocumentRefID != "" {
				if lo.Contains(docNames, string(rel.RefB.DocumentRefID)) {
					clone.RefB.DocumentRefID = ""
				} else {
					log.Warn(fmt.Sprintf("RefB: Could not find document name %s in the merge set", rel.RefB.DocumentRefID))
				}
			}

			if rel.RefA.ElementRefID != "" {
				namespace := doc.DocumentNamespace
				if rel.RefA.DocumentRefID != "" {
					namespace = getDocumentNamespace(string(rel.RefA.DocumentRefID), ms)
				}

				key := createLookupKey(namespace, string(rel.RefA.ElementRefID))
				if newID, ok := pkgMapper[key]; ok {
					clone.RefA.ElementRefID = common.ElementID(newID)
				} else if newID, ok := fileMapper[key]; ok {
					clone.RefA.ElementRefID = common.ElementID(newID)
				} else {
					log.Warn(fmt.Sprintf("RefA: Could not find element %s in the merge set", key))
				}
			}

			if rel.RefB.ElementRefID != "" {
				namespace := doc.DocumentNamespace
				if rel.RefB.DocumentRefID != "" {
					namespace = getDocumentNamespace(string(rel.RefB.DocumentRefID), ms)
				}

				key := createLookupKey(namespace, string(rel.RefB.ElementRefID))
				if newID, ok := pkgMapper[key]; ok {
					clone.RefB.ElementRefID = common.ElementID(newID)
				} else if newID, ok := fileMapper[key]; ok {
					clone.RefB.ElementRefID = common.ElementID(newID)
				} else {
					log.Warn(fmt.Sprintf("RefB: Could not find element %s in the merge set", key))
				}
			}

			// Add the relationship to the list
			relationships = append(relationships, clone)
		}
	}

	return relationships, nil
}

func getDescribedPkgs(ms *merge) []string {
	pkgs := []string{}

	for _, doc := range ms.in {
		for _, rel := range doc.Relationships {
			if rel.Relationship == common.TypeRelationshipDescribe {
				if rel.RefB.ElementRefID != "" {
					pkgs = append(pkgs, createLookupKey(doc.DocumentNamespace, string(rel.RefB.ElementRefID)))
				}
			}
		}
	}

	return pkgs
}

func writeSBOM(doc *v2_3.Document, m *merge) error {
	log := logger.FromContext(*m.settings.Ctx)
	var f io.Writer
	outName := "stdout"

	if m.settings.Output.File == "" {
		f = os.Stdout
	} else {
		var err error
		outName = m.settings.Output.File
		file, err := os.Create(m.settings.Output.File)
		if err != nil {
			return err
		}
		defer file.Close()
		f = file
	}

	buf, err := json.MarshalIndent(doc, "", " ")
	if err != nil {
		return err
	}

	_, err = f.Write(buf)
	if err != nil {
		return err
	}

	log.Debugf("wrote sbom %d bytes to %s with packages:%d, files:%d, deps:%d, snips:%d otherLics:%d, annotations:%d, externaldocRefs:%d",
		len(buf), outName,
		len(doc.Packages), len(doc.Files), len(doc.Relationships),
		len(doc.Snippets), len(doc.OtherLicenses), len(doc.Annotations),
		len(doc.ExternalDocumentReferences))

	return nil
}

func getDocumentNamespace(docName string, ms *merge) string {
	for _, doc := range ms.in {
		if doc.DocumentName == docName {
			return doc.DocumentNamespace
		}
	}

	return ""
}

// genHierarchicalContains generates CONTAINS relationships between each input SBOM's
// primary package and its non-primary packages. This is required because SPDX has no
// native component nesting — therefore hierarchy is expressed through
// CONTAINS(primary, child) relationships.
func genHierarchicalContains(ms *merge, pkgMapper map[string]string, existingRels []*spdx.Relationship) []*spdx.Relationship {
	log := logger.FromContext(*ms.settings.Ctx)

	// Build a set of existing (RefA, RefB) CONTAINS pairs to avoid duplicates
	existingPairs := make(map[string]bool)
	for _, rel := range existingRels {
		if rel.Relationship == common.TypeRelationshipContains {
			pairKey := fmt.Sprintf("%s->%s", rel.RefA.ElementRefID, rel.RefB.ElementRefID)
			existingPairs[pairKey] = true
		}
	}

	var newRels []*spdx.Relationship

	for _, doc := range ms.in {
		// Find primary package of this SBOM via DESCRIBES
		var primaryPkgID string
		for _, rel := range doc.Relationships {
			if rel.Relationship == common.TypeRelationshipDescribe && rel.RefB.ElementRefID != "" {
				lookupKey := createLookupKey(doc.DocumentNamespace, string(rel.RefB.ElementRefID))
				if mappedID, found := pkgMapper[lookupKey]; found {
					primaryPkgID = mappedID
				}
				break
			}
		}

		if primaryPkgID == "" {
			log.Warnf("could not find primary package for document %s, skipping CONTAINS generation", doc.DocumentName)
			continue
		}

		for _, pkg := range doc.Packages {
			pkgLookupKey := createLookupKey(doc.DocumentNamespace, string(pkg.PackageSPDXIdentifier))
			childPkgID, found := pkgMapper[pkgLookupKey]
			if !found {
				continue
			}

			if childPkgID == primaryPkgID {
				continue
			}

			// Skip if a CONTAINS already exists
			pairKey := fmt.Sprintf("%s->%s", common.ElementID(primaryPkgID), common.ElementID(childPkgID))
			if existingPairs[pairKey] {
				continue
			}

			newRels = append(newRels, &spdx.Relationship{
				RefA:                common.MakeDocElementID("", primaryPkgID),
				RefB:                common.MakeDocElementID("", childPkgID),
				Relationship:        common.TypeRelationshipContains,
				RelationshipComment: "sbomasm created contains relationship for hierarchical merge",
			})
		}
	}

	log.Debugf("generated %d CONTAINS relationships for hierarchical merge", len(newRels))
	return newRels
}
