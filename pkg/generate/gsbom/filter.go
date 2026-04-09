package gsbom

func FilterComponents(components []Component, includeTags, excludeTags []string) []Component {
	var filteredComponentsList []Component

	for _, c := range components {
		// Step 1: include filter
		if len(includeTags) > 0 {
			if !hasAnyTag(c.Tags, includeTags) {
				continue
			}
		}

		// Step 2: exclude filter
		if len(excludeTags) > 0 {
			if hasAnyTag(c.Tags, excludeTags) {
				continue
			}
		}

		filteredComponentsList = append(filteredComponentsList, c)
	}

	return filteredComponentsList
}

func hasAnyTag(componentTags, filterTags []string) bool {
	for _, ct := range componentTags {
		for _, ft := range filterTags {
			if ct == ft {
				return true
			}
		}
	}
	return false
}
