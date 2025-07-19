package comp

import (
	cydx "github.com/CycloneDX/cyclonedx-go"
	"github.com/interlynk-io/sbomasm/pkg/rm/field/cdx"
	"github.com/interlynk-io/sbomasm/pkg/rm/types"
)

type CdxCompTypeHandler struct {
	Component *cydx.Component
}

func (h *CdxCompTypeHandler) Select(params *types.RmParams) ([]interface{}, error) {
	return cdx.SelectTypeFromComponent(h.Component)
}

func (h *CdxCompTypeHandler) Filter(selected []interface{}, params *types.RmParams) ([]interface{}, error) {
	// return cdx.FilterTypeFromComponents(selected, params)
	return nil, nil // Filtering not implemented yet
}

func (h *CdxCompTypeHandler) Remove(targets []interface{}, params *types.RmParams) error {
	// return cdx.RemoveTypeFromComponents(h.Component, targets)
	return nil // Removal not implemented yet
}

func (h *CdxCompTypeHandler) Summary(selected []interface{}) {
	// cdx.RenderSummaryTypeFromComponents(selected)
}
