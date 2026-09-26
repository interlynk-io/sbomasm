// Copyright 2025 Interlynk.io
//
// SPDX-License-Identifier: Apache-2.0

package edit

import (
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/interlynk-io/sbomasm/v2/pkg/logger"
	spdx3 "github.com/interlynk-io/spdx-zen/model/v3.0.1"
	"github.com/interlynk-io/spdx-zen/parse"
	"go.uber.org/zap"
)

// spdx3EditDoc holds the working state for an SPDX 3.0 edit operation.
type spdx3EditDoc struct {
	doc    *parse.Document     // the full parsed SPDX 3.0 document
	pkg    *spdx3.Package      // the target package being mutated
	ci     *spdx3.CreationInfo // the document's CreationInfo (shared reference)
	config *configParams        // the user's edit configuration
}

// NewSpdx3EditDoc creates an edit document by locating the target package
// (primary or searcheeditor) and caching a pointer to the shared CreationInfo.
func NewSpdx3EditDoc(doc *parse.Document, c *configParams) (*spdx3EditDoc, error) {
	editor := &spdx3EditDoc{doc: doc, config: c}

	// The serializer extracts CreationInfo from each element's inline field,
	// not from doc.CreationInfo. For document-scoped mutations we target the
	// SpdxDocument's CreationInfo so the serializer sees the changes.
	if doc.SpdxDocument != nil {
		editor.ci = &doc.SpdxDocument.CreationInfo
	} else if doc.CreationInfo != nil {
		editor.ci = doc.CreationInfo
	}

	var pkg *spdx3.Package
	var err error

	switch c.search.subject {
	case SubjectPrimaryComponent:
		pkg, err = findPrimaryPackage(doc)
	case SubjectComponentNameVersion:
		pkg, err = findPackageByNameAndVersion(doc, c.search.name, c.search.version)
	}

	if err != nil {
		return nil, err
	}

	editor.pkg = pkg
	return editor, nil
}

// update applies all configured field mutations. Each mutation is a small,
// single-purpose function. Errors are logged but do not abort the sequence.
func (editor *spdx3EditDoc) update() {
	log := logger.FromContext(*editor.config.ctx)
	log.Debug("SPDX 3.0 updating sbom")

	for _, mutate := range editor.mutations() {
		if err := mutate.fn(); err != nil {
			editor.handleMutationError(log, mutate.name, err)
		}
	}
}

// mutation pairs a human-readable field name with the function that mutates it.
type mutation struct {
	name string
	fn   func() error
}

// mutations returns the ordered list of field mutations for SPDX 3.0.
func (editor *spdx3EditDoc) mutations() []mutation {
	return []mutation{
		{"name", editor.updateName},
		{"version", editor.updateVersion},
		{"supplier", editor.updateSupplier},
		{"authors", editor.updateDocumentAuthors},
		{"purl", editor.updatePurl},
		{"cpe", editor.updateCpe},
		{"licenses", editor.updateLicenses},
		{"hashes", editor.updateHashes},
		{"tools", editor.updateDocumentTools},
		{"copyright", editor.updateCopyright},
		{"lifeCycles", editor.updateDocumentLifeCycles},
		{"description", editor.updateDescription},
		{"repository", editor.updateRepository},
		{"type", editor.updateType},
		{"timeStamp", editor.updateDocumentTimeStamp},
	}
}

// handleMutationError logs the result of a single mutation based on its error
// value. No-configuration and not-supported are expected; everything else is
// surfaced as an informational message.
func (editor *spdx3EditDoc) handleMutationError(log *zap.SugaredLogger, name string, err error) {
	switch err {
	case errNoConfiguration:
		// field not requested; skip silently
	case errNotSupported:
		log.Infof("SPDX 3.0: %s not supported for subject %q", name, editor.config.search.subject)
	case errInvalidInput:
		log.Infof("SPDX 3.0: %s: %s", name, err)
	default:
		log.Infof("SPDX 3.0: error updating %s: %s", name, err)
	}
}

// -------------------------------------------------------------------------
// Direct field mutators (no reference traversal requireeditor)
// -------------------------------------------------------------------------

// updateName sets the package name.
func (editor *spdx3EditDoc) updateName() error {
	if !editor.config.shouldName() {
		return errNoConfiguration
	}
	if editor.config.search.subject == SubjectDocument {
		return errNotSupported
	}
	if editor.config.onMissing() && editor.pkg.Name != "" {
		return nil
	}
	editor.pkg.Name = editor.config.name
	return nil
}

// updateVersion sets the package version.
func (editor *spdx3EditDoc) updateVersion() error {
	if !editor.config.shouldVersion() {
		return errNoConfiguration
	}
	if editor.config.search.subject == SubjectDocument {
		return errNotSupported
	}
	if editor.config.onMissing() && editor.pkg.PackageVersion != "" {
		return nil
	}
	editor.pkg.PackageVersion = editor.config.version
	return nil
}

// updateDescription sets the description on the document or package.
func (editor *spdx3EditDoc) updateDescription() error {
	if !editor.config.shouldDescription() {
		return errNoConfiguration
	}

	if editor.config.search.subject == SubjectDocument {
		if editor.config.onMissing() && editor.doc.SpdxDocument.Description != "" {
			return nil
		}
		editor.doc.SpdxDocument.Description = editor.config.description
		return nil
	}

	if editor.config.onMissing() && editor.pkg.Description != "" {
		return nil
	}
	editor.pkg.Description = editor.config.description
	return nil
}

// updateCopyright sets the copyright text on the package.
func (editor *spdx3EditDoc) updateCopyright() error {
	if !editor.config.shouldCopyRight() {
		return errNoConfiguration
	}
	if editor.config.search.subject == SubjectDocument {
		return errNotSupported
	}
	if editor.config.onMissing() && editor.pkg.CopyrightText != "" {
		return nil
	}
	editor.pkg.CopyrightText = editor.config.copyright
	return nil
}

// spdx3PurposeMap maps CLI-friendly type names to SPDX 3.0 SoftwarePurpose
// enum values (lowercase camelCase per the JSON schema).
var spdx3PurposeMap = map[string]string{
	"application":      "application",
	"framework":          "framework",
	"library":            "library",
	"container":          "container",
	"operating-system":   "operatingSystem",
	"device":             "device",
	"firmware":           "firmware",
	"source":             "source",
	"archive":            "archive",
	"file":               "file",
	"install":            "install",
	"other":              "other",
	"bom":                "bom",
	"configuration":      "configuration",
	"data":               "data",
	"device-driver":      "deviceDriver",
	"disk-image":         "diskImage",
	"documentation":      "documentation",
	"evidence":           "evidence",
	"executable":         "executable",
	"filesystem-image":   "filesystemImage",
	"manifest":           "manifest",
	"model":              "model",
	"module":             "module",
	"patch":              "patch",
	"platform":           "platform",
	"requirement":        "requirement",
	"specification":      "specification",
	"test":               "test",
}

// updateType sets the primary purpose on the package using SPDX 3.0
// SoftwarePurpose enum values (lowercase camelCase per the JSON schema).
func (editor *spdx3EditDoc) updateType() error {
	if !editor.config.shouldTyp() {
		return errNoConfiguration
	}
	if editor.config.search.subject == SubjectDocument {
		return errNotSupported
	}

	purpose := spdx3.SoftwarePurpose(spdx3PurposeMap[strings.ToLower(editor.config.typ)])
	if purpose == "" {
		return errInvalidInput
	}

	if editor.config.onMissing() && editor.pkg.PrimaryPurpose != "" {
		return nil
	}
	editor.pkg.PrimaryPurpose = purpose
	return nil
}

// updateRepository sets the download location on the package.
func (editor *spdx3EditDoc) updateRepository() error {
	if !editor.config.shouldRepository() {
		return errNoConfiguration
	}
	if editor.config.search.subject == SubjectDocument {
		return errNotSupported
	}
	if editor.config.onMissing() && editor.pkg.DownloadLocation != "" {
		return nil
	}
	editor.pkg.DownloadLocation = editor.config.repository
	return nil
}

// updateTimeStamp sets the SpdxDocument's CreationInfo.Created timestamp to
// the current UTC time. This is a document-scoped field.
func (editor *spdx3EditDoc) updateDocumentTimeStamp() error {
	if !editor.config.shouldTimeStamp() {
		return errNoConfiguration
	}
	if editor.config.search.subject != SubjectDocument {
		return errNotSupported
	}
	if editor.doc.SpdxDocument == nil {
		return fmt.Errorf("document contains no SpdxDocument")
	}

	// Ensure ci points to the SpdxDocument's inline CreationInfo so the
	// serializer sees the change.
	editor.ci = &editor.doc.SpdxDocument.CreationInfo
	editor.ci.Created = time.Now().UTC()
	return nil
}

// -------------------------------------------------------------------------
// Reference field mutators (require SpdxID lookup)
// -------------------------------------------------------------------------

// updateSupplier sets the supplier on the package or adds a supplier comment
// to the document, depending on the subject scope.
func (editor *spdx3EditDoc) updateSupplier() error {
	if !editor.config.shouldSupplier() {
		return errNoConfiguration
	}

	if editor.config.search.subject == SubjectDocument {
		return editor.updateDocumentSupplier()
	}
	return editor.updatePackageSupplier()
}

// updateDocumentSupplier adds supplier information to the CreationInfo
// comment, mirroring the SPDX 2.3 behavior.
func (editor *spdx3EditDoc) updateDocumentSupplier() error {
	comment := fmt.Sprintf("%s (%s)", editor.config.supplier.name, editor.config.supplier.value)

	if editor.ci == nil {
		if editor.doc.SpdxDocument != nil {
			editor.ci = &editor.doc.SpdxDocument.CreationInfo
		} else {
			editor.ci = &spdx3.CreationInfo{}
			editor.doc.CreationInfo = editor.ci
		}
	}

	const prefix = "The supplier of this document are "
	if editor.ci.Comment == "" {
		editor.ci.Comment = prefix + comment
	} else if !strings.Contains(editor.ci.Comment, prefix) {
		editor.ci.Comment += "\n\n" + prefix + comment
	} else if editor.config.onAppend() && !strings.Contains(editor.ci.Comment, comment) {
		// Append mode: add new supplier if not already present.
		editor.ci.Comment += ", " + comment
	} else {
		// Overwrite mode: replace the entire supplier text with the new one.
		editor.ci.Comment = prefix + comment
	}
	return nil
}

// updatePackageSupplier follows the SuppliedBy reference and updates the
// referenced Organization. If no reference exists, it creates one.
func (editor *spdx3EditDoc) updatePackageSupplier() error {
	if editor.pkg.SuppliedBy == nil || editor.pkg.SuppliedBy.SpdxID == "" {
		return editor.createAndAttachSupplier()
	}
	return editor.mutateExistingSupplier()
}

// createAndAttachSupplier creates a new Organization element, appends it to
// the document, and sets the package's SuppliedBy reference to point to it.
func (editor *spdx3EditDoc) createAndAttachSupplier() error {
	org := editor.buildOrganizationFromConfig()
	editor.doc.Organizations = append(editor.doc.Organizations, org)
	editor.pkg.SuppliedBy = &spdx3.Agent{}
	editor.pkg.SuppliedBy.SpdxID = org.SpdxID
	return nil
}

// mutateExistingSupplier creates a new Organization for the supplier and
// updates the package's SuppliedBy reference to point to it. This preserves
// the old Organization so other packages that reference it are not affected.
func (editor *spdx3EditDoc) mutateExistingSupplier() error {
	if editor.config.onMissing() {
		// If the package already has a supplier reference, consider it present
		// and skip.
		return nil
	}
	org := editor.buildOrganizationFromConfig()
	editor.doc.Organizations = append(editor.doc.Organizations, org)
	editor.pkg.SuppliedBy = &spdx3.Agent{}
	editor.pkg.SuppliedBy.SpdxID = org.SpdxID
	return nil
}

// buildOrganizationFromConfig creates a new Organization element from the
// configured supplier name. If the supplier value looks like an email, it
// is stored as an external identifier (per SPDX 3.0 convention).
func (editor *spdx3EditDoc) buildOrganizationFromConfig() *spdx3.Organization {
	orgID := editor.generateElementSpdxID("org")
	org := &spdx3.Organization{}
	org.SpdxID = orgID
	org.Name = editor.config.supplier.name
	if strings.Contains(editor.config.supplier.value, "@") {
		org.ExternalIdentifier = []spdx3.ExternalIdentifier{
			{
				ExternalIdentifierType: ExtIDTypeEmail,
				Identifier:             editor.config.supplier.value,
			},
		}
	}
	org.CreationInfo = editor.documentCreationInfo()
	return org
}

// updateAuthors sets or appends document authors by mutating the
// CreationInfo.CreatedBy agent references.
func (editor *spdx3EditDoc) updateDocumentAuthors() error {
	if !editor.config.shouldAuthors() {
		return errNoConfiguration
	}
	if editor.config.search.subject != SubjectDocument {
		return errNotSupported
	}

	if editor.ci == nil {
		if editor.doc.SpdxDocument != nil {
			editor.ci = &editor.doc.SpdxDocument.CreationInfo
		} else {
			editor.ci = &spdx3.CreationInfo{}
			editor.doc.CreationInfo = editor.ci
		}
	}

	// Check missing BEFORE any side effects.  If a Person already exists in
	// CreatedBy and --missing was requested, skip.  An Organization or other
	// non-Person agent does not count as an author.
	if editor.config.onMissing() && editor.hasPersonInCreatedBy() {
		return nil
	}

	var newAgents []spdx3.Agent

	if editor.config.onAppend() || editor.config.onMissing() {
		// Append / missing: create new Person elements and add them alongside
		// existing CreatedBy entries.  Organizations, Tools, etc. are preserved.
		// Skip duplicates — a Person already in CreatedBy is not added again.
		for _, author := range editor.config.authors {
			person := editor.findOrCreatePerson(author.name, author.value)
			if editor.isInCreatedBy(person.SpdxID) {
				continue // already referenced, skip
			}
			agent := spdx3.Agent{}
			agent.SpdxID = person.SpdxID
			newAgents = append(newAgents, agent)
		}
		editor.ci.CreatedBy = append(editor.ci.CreatedBy, newAgents...)
	} else {
		// Overwrite mode: replace only Person entries in CreatedBy.  Reuse
		// SpdxIDs from existing Person elements when possible, and preserve
		// non-Person agents (Organization, Tool, etc.).
		oldIDs := editor.collectCreatedByIDs()
		for _, author := range editor.config.authors {
			person := editor.findOrUpdatePerson(author.name, author.value, oldIDs)
			agent := spdx3.Agent{}
			agent.SpdxID = person.SpdxID
			newAgents = append(newAgents, agent)
			delete(oldIDs, person.SpdxID) // mark as reused
		}
		// Preserve non-Person agents from the old CreatedBy.
		var preserved []spdx3.Agent
		for _, agent := range editor.ci.CreatedBy {
			if !editor.isPersonAgent(agent) {
				preserved = append(preserved, agent)
			}
		}
		editor.ci.CreatedBy = append(preserved, newAgents...)
		// Remove Person elements whose SpdxIDs were in the old CreatedBy
		// but were not reused for the new authors.
		editor.removeOrphanedPersons(oldIDs)
	}

	return nil
}

// collectCreatedByIDs returns a set of SpdxIDs referenced by the current
// CreationInfo.CreatedBy slice.
func (editor *spdx3EditDoc) collectCreatedByIDs() map[string]struct{} {
	ids := make(map[string]struct{}, len(editor.ci.CreatedBy))
	for _, agent := range editor.ci.CreatedBy {
		if agent.SpdxID != "" {
			ids[agent.SpdxID] = struct{}{}
		}
	}
	return ids
}

// removeOrphanedPersons deletes Person elements whose SpdxIDs are in the
// provided set and are no longer referenced by CreationInfo.CreatedBy.
func (editor *spdx3EditDoc) removeOrphanedPersons(orphanIDs map[string]struct{}) {
	if len(orphanIDs) == 0 {
		return
	}
	// Build a set of IDs still referenced by the current CreatedBy.
	referenced := make(map[string]struct{}, len(editor.ci.CreatedBy))
	for _, agent := range editor.ci.CreatedBy {
		if agent.SpdxID != "" {
			referenced[agent.SpdxID] = struct{}{}
		}
	}
	var kept []*spdx3.Person
	for _, person := range editor.doc.Persons {
		if _, isOrphan := orphanIDs[person.SpdxID]; isOrphan {
			if _, stillReferenced := referenced[person.SpdxID]; !stillReferenced {
				continue // drop this orphaned Person
			}
		}
		kept = append(kept, person)
	}
	editor.doc.Persons = kept
}

// hasPersonInCreatedBy returns true if any Agent in CreationInfo.CreatedBy
// references a Person element in the document.
func (editor *spdx3EditDoc) hasPersonInCreatedBy() bool {
	for _, agent := range editor.ci.CreatedBy {
		if agent.SpdxID == "" {
			continue
		}
		for _, person := range editor.doc.Persons {
			if person.SpdxID == agent.SpdxID {
				return true
			}
		}
	}
	return false
}

// isInCreatedBy returns true if the given SpdxID is already referenced by the
// current CreationInfo.CreatedBy slice.
func (editor *spdx3EditDoc) isInCreatedBy(spdxID string) bool {
	for _, agent := range editor.ci.CreatedBy {
		if agent.SpdxID == spdxID {
			return true
		}
	}
	return false
}

// isPersonAgent returns true if the Agent's SpdxID references a Person element
// in the document.
func (editor *spdx3EditDoc) isPersonAgent(agent spdx3.Agent) bool {
	for _, person := range editor.doc.Persons {
		if person.SpdxID == agent.SpdxID {
			return true
		}
	}
	return false
}

// findOrUpdatePerson searches for an existing Person in the document.  If
// overwriteIDs is non-empty, it first tries to find a Person whose SpdxID
// is in that set (meaning it was previously an author) and updates its
// name/email in place.  Otherwise it falls back to normal find-or-create
// logic.
func (editor *spdx3EditDoc) findOrUpdatePerson(name, email string, overwriteIDs map[string]struct{}) *spdx3.Person {
	// Try to reuse a Person that was previously in CreatedBy.
	for _, person := range editor.doc.Persons {
		if _, ok := overwriteIDs[person.SpdxID]; ok {
			// Update in place so the SpdxID is preserved.
			person.Name = name
			person.ExternalIdentifier = []spdx3.ExternalIdentifier{
				{ExternalIdentifierType: ExtIDTypeEmail, Identifier: email},
			}
			return person
		}
	}
	// No existing author Person to reuse; fall back to normal lookup.
	return editor.findOrCreatePerson(name, email)
}

// updateTools sets or appends document tools by mutating the
// CreationInfo.CreatedUsing slice. The sbomasm tool is automatically
// injected if not already present.
func (editor *spdx3EditDoc) updateDocumentTools() error {
	if !editor.config.shouldTools() {
		return errNoConfiguration
	}
	if editor.config.search.subject != SubjectDocument {
		return errNotSupported
	}

	if editor.ci == nil {
		if editor.doc.SpdxDocument != nil {
			editor.ci = &editor.doc.SpdxDocument.CreationInfo
		} else {
			editor.ci = &spdx3.CreationInfo{}
			editor.doc.CreationInfo = editor.ci
		}
	}

	newTools := editor.buildToolList()

	// Inject sbomasm tool if not already present
	sbomasmTool := editor.findOrCreateTool(SBOMASM, SBOMASM_VERSION)
	newTools = editor.mergeTools(newTools, []spdx3.Tool{*sbomasmTool})

	if editor.config.onMissing() && len(editor.ci.CreatedUsing) > 0 {
		return nil
	}
	if editor.config.onAppend() {
		editor.ci.CreatedUsing = editor.mergeTools(editor.ci.CreatedUsing, newTools)
	} else {
		editor.ci.CreatedUsing = newTools
	}
	return nil
}

// buildToolList creates Tool values for each configured tool, creating Tool
// elements in the document when necessary.
func (editor *spdx3EditDoc) buildToolList() []spdx3.Tool {
	var tools []spdx3.Tool
	for _, tool := range editor.config.tools {
		t := editor.findOrCreateTool(tool.name, tool.value)
		tools = append(tools, *t)
	}
	return tools
}

// -------------------------------------------------------------------------
// Collection field mutators (slice manipulation)
// -------------------------------------------------------------------------

// updateHashes replaces or appends hash entries in the package's
// VerifiedUsing slice.
func (editor *spdx3EditDoc) updateHashes() error {
	if !editor.config.shouldHashes() {
		return errNoConfiguration
	}
	if editor.config.search.subject == SubjectDocument {
		return errNotSupported
	}

	newHashes := editor.buildHashList()

	if editor.config.onMissing() && len(editor.pkg.VerifiedUsing) > 0 {
		return nil
	}
	if editor.config.onAppend() {
		editor.pkg.VerifiedUsing = append(editor.pkg.VerifiedUsing, newHashes...)
	} else {
		editor.pkg.VerifiedUsing = newHashes
	}
	return nil
}

// buildHashList converts the configured hash tuples into Hash structs.
// Algorithm names are normalised to lowercase to match the SPDX 3.0 JSON
// schema enum (e.g. "SHA256" → "sha256").
func (editor *spdx3EditDoc) buildHashList() []interface{} {
	var hashes []interface{}
	for _, h := range editor.config.hashes {
		hash := spdx3.Hash{
			Algorithm: spdx3.HashAlgorithm(strings.ToLower(h.name)),
			HashValue: h.value,
		}
		hashes = append(hashes, hash)
	}
	return hashes
}

// updatePurl replaces or appends the purl external identifier on the package.
func (editor *spdx3EditDoc) updatePurl() error {
	if !editor.config.shouldPurl() {
		return errNoConfiguration
	}
	if editor.config.search.subject == SubjectDocument {
		return errNotSupported
	}

	purl := spdx3.ExternalIdentifier{
		ExternalIdentifierType: ExtIDTypePurl,
		Identifier:             editor.config.purl,
	}

	editor.applyExternalIdentifier(ExtIDTypePurl, purl)
	return nil
}

// updateCpe replaces or appends the cpe external identifier on the package.
func (editor *spdx3EditDoc) updateCpe() error {
	if !editor.config.shouldCpe() {
		return errNoConfiguration
	}
	if editor.config.search.subject == SubjectDocument {
		return errNotSupported
	}

	cpe := spdx3.ExternalIdentifier{
		ExternalIdentifierType: ExtIDTypeCpe23,
		Identifier:             editor.config.cpe,
	}

	editor.applyExternalIdentifier(ExtIDTypeCpe23, cpe)
	return nil
}

// applyExternalIdentifier applies an external identifier mutation respecting
// the overwrite, missing, and append modes.
func (editor *spdx3EditDoc) applyExternalIdentifier(extType string, newID spdx3.ExternalIdentifier) {
	switch {
	case editor.config.onMissing() && editor.hasExternalIdentifier(extType):
		// already exists; do nothing
	case editor.config.onAppend():
		editor.pkg.ExternalIdentifier = append(editor.pkg.ExternalIdentifier, newID)
	default:
		// overwrite: keep identifiers of other types, replace this type
		filtered := editor.filterExternalIdentifiers(extType)
		editor.pkg.ExternalIdentifier = append(filtered, newID)
	}
}

// -------------------------------------------------------------------------
// -------------------------------------------------------------------------
// License mutator (relationship-based for components, DataLicense for document)
// -------------------------------------------------------------------------

// updateLicenses creates or updates the license for the target scope.
// For components: creates a hasConcludedLicense relationship.
// For documents: sets SpdxDocument.DataLicense to a LicenseExpression.
func (editor *spdx3EditDoc) updateLicenses() error {
	if !editor.config.shouldLicenses() {
		return errNoConfiguration
	}

	licenseExpr := editor.buildLicenseExpression()
	licExpr := editor.findOrCreateLicenseExpression(licenseExpr)

	if editor.config.search.subject == SubjectDocument {
		return editor.updateDocumentLicense(licExpr)
	}
	return editor.updatePackageLicense(licExpr)
}

// updateDocumentLicense sets the SpdxDocument's DataLicense to reference
// the given LicenseExpression element.
func (editor *spdx3EditDoc) updateDocumentLicense(licExpr *spdx3.LicenseExpression) error {
	if editor.doc.SpdxDocument == nil {
		return fmt.Errorf("document contains no SpdxDocument")
	}

	if editor.config.onMissing() && editor.doc.SpdxDocument.DataLicense != nil {
		return nil
	}

	editor.doc.SpdxDocument.DataLicense = &spdx3.AnyLicenseInfo{
		Element: spdx3.Element{SpdxID: licExpr.SpdxID},
	}
	return nil
}

// updatePackageLicense creates or updates the hasConcludedLicense
// relationship for the target package, pointing to the given license
// expression.
func (editor *spdx3EditDoc) updatePackageLicense(licExpr *spdx3.LicenseExpression) error {
	rel := editor.findLicenseRelationship()
	if rel == nil {
		editor.createLicenseRelationship(licExpr)
	} else {
		rel.To = []spdx3.Element{{SpdxID: licExpr.SpdxID}}
	}
	return nil
}

// buildLicenseExpression joins configured license names with " OR ".
// SPDX special values (NOASSERTION, NONE) are upper-cased; everything else
// preserves the original casing.
func (editor *spdx3EditDoc) buildLicenseExpression() string {
	parts := make([]string, 0, len(editor.config.licenses))
	for _, lic := range editor.config.licenses {
		lower := strings.ToLower(lic.name)
		var normalized string
		if lower == "noassertion" || lower == "none" {
			normalized = strings.ToUpper(lic.name)
		} else {
			normalized = lic.name
		}
		parts = append(parts, normalized)
	}
	return strings.Join(parts, " OR ")
}

// findOrCreateLicenseExpression searches for an existing license expression
// with the given text. If none exists, it creates a new LicenseExpression
// element, copies the document's CreationInfo into it, appends it to the
// document, and returns it.
func (editor *spdx3EditDoc) findOrCreateLicenseExpression(expr string) *spdx3.LicenseExpression {
	for _, licExpr := range editor.doc.LicenseExpressions {
		if licExpr.LicenseExpression == expr {
			return licExpr
		}
	}

	licID := editor.generateElementSpdxID("license")
	licExpr := &spdx3.LicenseExpression{}
	licExpr.SpdxID = licID
	licExpr.LicenseExpression = expr
	licExpr.CreationInfo = editor.documentCreationInfo()
	editor.doc.LicenseExpressions = append(editor.doc.LicenseExpressions, licExpr)
	return licExpr
}

// findLicenseRelationship searches for an existing hasConcludedLicense
// relationship originating from the target package.
func (editor *spdx3EditDoc) findLicenseRelationship() *spdx3.Relationship {
	if editor.pkg == nil || editor.pkg.SpdxID == "" {
		return nil
	}
	for _, rel := range editor.doc.Relationships {
		if rel.RelationshipType == RelTypeHasConcludedLicense &&
			rel.From.SpdxID == editor.pkg.SpdxID {
			return rel
		}
	}
	return nil
}

// createLicenseRelationship creates a new hasConcludedLicense relationship
// from the target package to the given license expression, copying the
// document's CreationInfo into the new relationship.
func (editor *spdx3EditDoc) createLicenseRelationship(licExpr *spdx3.LicenseExpression) {
	relID := editor.generateElementSpdxID("rel")
	rel := &spdx3.Relationship{
		Element: spdx3.Element{
			SpdxID: relID,
		},
		RelationshipType: RelTypeHasConcludedLicense,
		From:             spdx3.Element{SpdxID: editor.pkg.SpdxID},
		To:               []spdx3.Element{{SpdxID: licExpr.SpdxID}},
	}
	rel.CreationInfo = editor.documentCreationInfo()
	editor.doc.Relationships = append(editor.doc.Relationships, rel)
}

// -------------------------------------------------------------------------
// Lifecycle / SBOM type mutator
// -------------------------------------------------------------------------

// lifecycleToSbomType maps CLI lifecycle values to SPDX 3.0 SbomType enum
// values. The CLI uses CycloneDX-style phase names; SPDX 3.0 uses typed Sbom
// categories.
var lifecycleToSbomType = map[string]string{
	"design":     "design",
	"source":     "source",
	"pre-build":  "build",
	"build":      "build",
	"post-build": "analyzed",
}

// updateDocumentLifeCycles finds or creates a software_Sbom element and sets
// its sbomType to the mapped SPDX 3.0 values. This is the correct SPDX 3.0
// representation of SBOM lifecycle information.
func (editor *spdx3EditDoc) updateDocumentLifeCycles() error {
	if !editor.config.shouldLifeCycle() {
		return errNoConfiguration
	}
	if editor.config.search.subject != SubjectDocument {
		return errNotSupported
	}

	// Validate and map lifecycle phases to SPDX 3.0 SbomType values.
	var sbomTypes []spdx3.SbomType
	for _, phase := range editor.config.lifecycles {
		lowerPhase := strings.ToLower(phase)
		if _, ok := supportedSPDXMetadataLifeCycle[lowerPhase]; !ok {
			return errInvalidInput
		}
		sbomTypes = append(sbomTypes, spdx3.SbomType(lifecycleToSbomType[lowerPhase]))
	}

	// Find an existing Sbom element or create one.
	sbom := editor.findOrCreateSbom()

	if editor.config.onMissing() && len(sbom.SbomType) > 0 {
		return nil
	}
	if editor.config.onAppend() {
		sbom.SbomType = editor.mergeSbomTypes(sbom.SbomType, sbomTypes)
	} else {
		sbom.SbomType = sbomTypes
	}
	return nil
}

// findOrCreateSbom searches for an existing Sbom element in the document. If
// none exists, it creates a new one with a generated SpdxID, copies the
// document's CreationInfo into it, and appends it to doc.Sboms.
func (editor *spdx3EditDoc) findOrCreateSbom() *spdx3.Sbom {
	if len(editor.doc.Sboms) > 0 {
		return editor.doc.Sboms[0]
	}

	sbomID := editor.generateElementSpdxID("sbom")
	sbom := &spdx3.Sbom{}
	sbom.SpdxID = sbomID
	if editor.doc.SpdxDocument != nil {
		sbom.Name = editor.doc.SpdxDocument.Name
	}
	sbom.CreationInfo = editor.documentCreationInfo()
	editor.doc.Sboms = append(editor.doc.Sboms, sbom)
	return sbom
}

// mergeSbomTypes returns a new slice containing all types from a and b,
// deduplicated.
func (editor *spdx3EditDoc) mergeSbomTypes(a, b []spdx3.SbomType) []spdx3.SbomType {
	seen := make(map[string]struct{}, len(a)+len(b))
	var merged []spdx3.SbomType
	for _, t := range a {
		key := string(t)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		merged = append(merged, t)
	}
	for _, t := range b {
		key := string(t)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		merged = append(merged, t)
	}
	return merged
}

// -------------------------------------------------------------------------
// Element lookup helpers (one function per lookup type)
// -------------------------------------------------------------------------

// findOrganizationByID searches the document for an organization with the
// given SpdxID. Returns nil if not found.
func (editor *spdx3EditDoc) findOrganizationByID(spdxID string) *spdx3.Organization {
	for _, org := range editor.doc.Organizations {
		if org.SpdxID == spdxID {
			return org
		}
	}
	return nil
}

// findOrCreatePerson searches for an existing person by name. If not found,
// it creates a new Person element with the email stored as an external
// identifier (per SPDX 3.0 convention), copies the document's CreationInfo
// into it, appends it to the document, and returns it.
func (editor *spdx3EditDoc) findOrCreatePerson(name, email string) *spdx3.Person {
	for _, person := range editor.doc.Persons {
		if person.Name == name {
			return person
		}
	}

	personID := editor.generateElementSpdxID("person")
	person := &spdx3.Person{}
	person.SpdxID = personID
	person.Name = name
	person.ExternalIdentifier = []spdx3.ExternalIdentifier{
		{
			ExternalIdentifierType: ExtIDTypeEmail,
			Identifier:             email,
		},
	}
	person.CreationInfo = editor.documentCreationInfo()
	editor.doc.Persons = append(editor.doc.Persons, person)
	return person
}

// findOrCreateTool searches for an existing tool by full display name. If not
// found, it creates a new Tool element, copies the document's CreationInfo
// into it, appends it to the document, and returns it.
func (editor *spdx3EditDoc) findOrCreateTool(name, version string) *spdx3.Tool {
	fullName := fmt.Sprintf("%s (%s)", name, version)
	for _, tool := range editor.doc.Tools {
		if tool.Name == fullName {
			return tool
		}
	}

	toolID := editor.generateElementSpdxID("tool")
	tool := &spdx3.Tool{
		Element: spdx3.Element{
			SpdxID: toolID,
			Name:   fullName,
		},
	}
	tool.CreationInfo = editor.documentCreationInfo()
	editor.doc.Tools = append(editor.doc.Tools, tool)
	return tool
}

// -------------------------------------------------------------------------
// ExternalIdentifier helpers
// -------------------------------------------------------------------------

// hasExternalIdentifier returns true if the package already has an external
// identifier of the given type (e.g. "purl", "cpe23Type").
func (editor *spdx3EditDoc) hasExternalIdentifier(extType string) bool {
	for _, ext := range editor.pkg.ExternalIdentifier {
		if string(ext.ExternalIdentifierType) == extType {
			return true
		}
	}
	return false
}

// filterExternalIdentifiers returns all external identifiers EXCEPT those
// matching the given type. This is used during overwrite mode to remove
// old entries before adding the new one.
func (editor *spdx3EditDoc) filterExternalIdentifiers(extType string) []spdx3.ExternalIdentifier {
	var result []spdx3.ExternalIdentifier
	for _, ext := range editor.pkg.ExternalIdentifier {
		if string(ext.ExternalIdentifierType) != extType {
			result = append(result, ext)
		}
	}
	return result
}

// -------------------------------------------------------------------------
// Agent slice helpers
// -------------------------------------------------------------------------

// mergeAgents returns a new slice containing all agents from a and b,
// deduplicated by SpdxID.
func (editor *spdx3EditDoc) mergeAgents(a, b []spdx3.Agent) []spdx3.Agent {
	seen := make(map[string]struct{}, len(a)+len(b))
	var merged []spdx3.Agent

	for _, agent := range a {
		if _, ok := seen[agent.SpdxID]; ok {
			continue
		}
		seen[agent.SpdxID] = struct{}{}
		merged = append(merged, agent)
	}

	for _, agent := range b {
		if _, ok := seen[agent.SpdxID]; ok {
			continue
		}
		seen[agent.SpdxID] = struct{}{}
		merged = append(merged, agent)
	}

	return merged
}

// mergeTools returns a new slice containing all tools from a and b,
// deduplicated by SpdxID.
func (editor *spdx3EditDoc) mergeTools(a, b []spdx3.Tool) []spdx3.Tool {
	seen := make(map[string]struct{}, len(a)+len(b))
	var merged []spdx3.Tool

	for _, tool := range a {
		if _, ok := seen[tool.SpdxID]; ok {
			continue
		}
		seen[tool.SpdxID] = struct{}{}
		merged = append(merged, tool)
	}

	for _, tool := range b {
		if _, ok := seen[tool.SpdxID]; ok {
			continue
		}
		seen[tool.SpdxID] = struct{}{}
		merged = append(merged, tool)
	}

	return merged
}

// -------------------------------------------------------------------------
// SpdxID generation
// -------------------------------------------------------------------------

// generateElementSpdxID creates a deterministic SPDX ID for a new element.
// The format is: https://example.org/{prefix}-{uuid}.
func (editor *spdx3EditDoc) generateElementSpdxID(prefix string) string {
	return fmt.Sprintf("https://example.org/%s-%s", prefix, uuid.New().String())
}

// -------------------------------------------------------------------------
// Document-wide helpers
// -------------------------------------------------------------------------

// documentCreationInfo returns the CreationInfo value that should be stamped
// onto every newly created element. It prefers the SpdxDocument's inline
// CreationInfo (so the serializer groups the new element with the existing
// document elements) and falls back to the doc-level pointer only when the
// SpdxDocument is absent.
func (editor *spdx3EditDoc) documentCreationInfo() spdx3.CreationInfo {
	// New elements (Person, Tool, etc.) should share the base CreationInfo,
	// not the SpdxDocument's potentially-mutated one.  If we return the
	// SpdxDocument's CreationInfo here, newly-created elements capture an
	// intermediate state (e.g. already includes previously-appended authors)
	// and the serializer emits an extra blank node that appears orphaned.
	if editor.doc.CreationInfo != nil {
		return *editor.doc.CreationInfo
	}
	if editor.doc.SpdxDocument != nil {
		return editor.doc.SpdxDocument.CreationInfo
	}
	return spdx3.CreationInfo{}
}
