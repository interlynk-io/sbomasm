package gsbom

import "fmt"

func componentKey(c Component) string {
	return c.Name + "@" + c.Version
}

func MergeAll(componentLists [][]Component) []Component {
	var merged []Component

	for _, group := range componentLists {
		merged = append(merged, group...)
	}

	return merged
}

func DeduplicateComponents(components []Component) ([]Component, []error) {
	var result []Component
	var warnings []error

	seen := make(map[string]bool)

	for _, c := range components {
		key := componentKey(c)

		if seen[key] {
			warnings = append(warnings, fmt.Errorf("duplicate component: %s", key))
			continue
		}

		seen[key] = true
		result = append(result, c)
	}

	return result, warnings
}
