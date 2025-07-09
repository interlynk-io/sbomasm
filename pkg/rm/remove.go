package rm

import (
	"context"
	"fmt"
	"strings"

	cydx "github.com/CycloneDX/cyclonedx-go"
	"github.com/interlynk-io/sbomasm/pkg/rm/types"
)

func rmCycloneDX(ctx context.Context, bom *cydx.BOM, params *types.RmParams) error {
	switch params.Kind {
	case types.FieldRemoval:
		return handleCDXFieldRemoval(ctx, bom, params)
	case types.ComponentRemoval:
		// TODO: Implement
		return fmt.Errorf("component removal not implemented yet")
	case types.DependencyRemoval:
		// TODO: Implement
		return fmt.Errorf("dependency removal not implemented yet")
	default:
		// return sbom.ErrInvalidRemovalKind
		return fmt.Errorf("invalid removal kind: %s", params.Kind)
	}
}

func handleCDXFieldRemoval(ctx context.Context, bom *cydx.BOM, params *types.RmParams) error {
	switch params.Scope {
	case "document":
		return handleFieldFromCDXDocument(ctx, bom, params)
	case "component":
		// return removeFieldFromCDXComponents(ctx, bom, params)
	case "dependency":
		// return removeFieldFromCDXDependencies(ctx, bom, params)
	default:
		return fmt.Errorf("invalid scope for field removal: %s", params.Scope)
	}
	return fmt.Errorf("field removal for scope %q not implemented", params.Scope)
}

func handleFieldFromCDXDocument(ctx context.Context, bom *cydx.BOM, params *types.RmParams) error {
	// no metadata, nothing to remove
	if bom.Metadata == nil {
		return nil
	}

	selected, err := selectFieldFromCDXDocument(bom, params)
	if err != nil {
		return err
	}

	if params.DryRun {
		fmt.Println("Matched entries (dry-run):")
		for _, e := range selected {
			fmt.Printf("- %v\n", e)
		}
		return nil
	}

	return removeSelectedFieldFromCDXDocument(bom, selected, params)
}

func selectFieldFromCDXDocument(bom *cydx.BOM, params *types.RmParams) ([]interface{}, error) {
	field := strings.ToLower(params.Field)

	switch field {
	case "author":
		return selectAuthorFromMetadata(bom, params)
	case "supplier":
		// return selectSupplierFromMetadata(bom, params)
	case "timestamp":
		// return selectTimestampFromMetadata(bom)
	case "tool":
		// return selectToolFromMetadata(bom, params)
	case "license":
		// return selectLicenseFromMetadata(bom, params)
	case "description":
		// return selectDescriptionFromMetadata(bom, params)
	case "repository":
		// return selectRepositoryFromMetadata(bom, params)
	default:
		return nil, fmt.Errorf("unsupported document field for CycloneDX: %s", field)
	}
	return nil, fmt.Errorf("field selection for %q not implemented", field)
}

func selectAuthorFromMetadata(bom *cydx.BOM, params *types.RmParams) ([]interface{}, error) {
	if bom.Metadata.Authors == nil || len(*bom.Metadata.Authors) == 0 {
		return nil, nil
	}

	var selected []interface{}
	for _, author := range *bom.Metadata.Authors {
		matchKey := params.Key == "" || author.Name == params.Key
		matchValue := params.Value == "" || author.Email == params.Value

		if matchKey && matchValue {
			selected = append(selected, author)
		}
	}
	return selected, nil
}

func removeSelectedFieldFromCDXDocument(bom *cydx.BOM, selected []interface{}, params *types.RmParams) error {
	switch strings.ToLower(params.Field) {
	case "author":
		return removeAuthorFromMetadata(bom, selected, params)
	case "supplier":
		// return removeSupplierFromMetadata(bom, selected, params)
	case "timestamp":
		// return removeTimestampFromMetadata(bom, selected, params)
	case "tool":
		// return removeToolFromMetadata(bom, selected, params)
	case "license":
		// return removeLicenseFromMetadata(bom, selected, params)
	case "description":
		// return removeDescriptionFromMetadata(bom, selected, params)
	}

	return fmt.Errorf("removal for field %q not implemented", params.Field)
}

func removeAuthorFromMetadata(bom *cydx.BOM, selected []interface{}, params *types.RmParams) error {
	if bom.Metadata == nil || bom.Metadata.Authors == nil {
		return nil
	}

	var filtered []cydx.OrganizationalContact
	for _, author := range *bom.Metadata.Authors {
		match := false
		for _, sel := range selected {
			if matchAuthor(sel, author) {
				match = true
				break
			}
		}
		if !match {
			filtered = append(filtered, author)
		}
	}
	bom.Metadata.Authors = &filtered
	return nil
}

func matchAuthor(sel interface{}, author cydx.OrganizationalContact) bool {
	candidate, ok := sel.(cydx.OrganizationalContact)
	if !ok {
		return false
	}
	return candidate.Name == author.Name && candidate.Email == author.Email
}
