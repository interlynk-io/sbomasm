package types

import "fmt"

var ValidFields = map[string][]string{
	"document": {
		"author",
		"supplier",
		"timestamp",
		"tool",
		"lifecycle",
		"description",
		"license",
	},
	"component": {
		"author",
		"supplier",
		"type",
		"repository",
		"cpe",
		"hash",
		"license",
		"copyright",
		"purl",
		"description",
	},
	"dependency": {
		"from",
		"to",
	},
}

// Validate checks if the removal parameters are valid.
func (p *RmParams) Validate() error {
	// conflict Checks First
	if p.Field != "" && p.IsComponent {
		return fmt.Errorf("conflicting flags: '--field' and '--component' cannot be used together")
	}

	if p.Field != "" && p.IsDependency {
		return fmt.Errorf("conflicting flags: '--field' and '--dependency' cannot be used together")
	}

	if p.IsComponent && p.IsDependency {
		return fmt.Errorf("conflicting flags: '--component' and '--dependency' cannot be used together")
	}

	// CASE 1: Field-based removal
	if p.Field != "" {
		if p.Scope == "" {
			return fmt.Errorf("missing required flag: --scope is required when using --field")
		}

		if p.Scope != "document" && p.Scope != "component" && p.Scope != "dependency" {
			return fmt.Errorf("invalid value for --scope: must be 'document', 'component', or 'dependency'")
		}

		// component-specific scope checks
		if p.Scope == "component" {
			hasName := p.ComponentName != ""
			hasVersion := p.ComponentVersion != ""

			if (hasName && !hasVersion) || (!hasName && hasVersion) {
				return fmt.Errorf("--name and --version must be used together when removing a field from a specific component")
			}

			if !hasName && !hasVersion && !p.All {
				return fmt.Errorf("component field removal requires --name and --version or --all")
			}
		}

		// dependency-specific scope checks (future extension placeholder)
		if p.Scope == "dependency" {
			// Optionally enforce filters here later
		}

		if allowedFields, ok := ValidFields[p.Scope]; ok {
			if !contains(allowedFields, p.Field) {
				return fmt.Errorf("invalid field '%s' for scope '%s'. Allowed values are: %v", p.Field, p.Scope, allowedFields)
			}
		}

		return nil
	}

	// CASE 2: Component Removal
	if p.IsComponent {
		hasName := p.ComponentName != ""
		hasVersion := p.ComponentVersion != ""

		// deal with single component
		if hasName || hasVersion {
			if !hasName || !hasVersion {
				return fmt.Errorf("both --name and --version must be provided for component removal")
			}
			return nil
		}

		// deal with bulk component
		if p.All {
			if p.Key != "" || p.Value != "" {
				return nil
			}
			return fmt.Errorf("bulk component removal with --all requires at least --key or --value for matching")
		}

		return fmt.Errorf("invalid component removal: either use --name and --version, or --key/--value with --all")
	}

	// CASE 3: Dependency Removal
	if p.IsDependency {
		if p.DependencyID == "" {
			return fmt.Errorf("--dependency requires --id to be specified")
		}
		return nil
	}

	return fmt.Errorf("invalid command: specify at least one valid removal operation (e.g., --field, --component, or --dependency)")
}

func contains(allowedFields []string, field string) bool {
	for _, v := range allowedFields {
		if v == field {
			return true
		}
	}
	return false
}
