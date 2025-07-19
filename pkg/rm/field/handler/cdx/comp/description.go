package comp

import (
	cydx "github.com/CycloneDX/cyclonedx-go"
	"github.com/interlynk-io/sbomasm/pkg/rm/field/cdx"
	"github.com/interlynk-io/sbomasm/pkg/rm/types"
)

type CdxCompDescriptionHandler struct {
	Component *cydx.Component
}

func (h *CdxCompDescriptionHandler) Select(params *types.RmParams) ([]interface{}, error) {
	return cdx.SelectDescriptionFromComponent(h.Component)
}

func (h *CdxCompDescriptionHandler) Filter(selected []interface{}, params *types.RmParams) ([]interface{}, error) {
	// return cdx.FilterDescriptionFromComponents(selected, params)
	return nil, nil // Filtering not implemented yet
}

func (h *CdxCompDescriptionHandler) Remove(targets []interface{}, params *types.RmParams) error {
	// return cdx.RemoveDescriptionFromComponents(h.Component, targets)
	return nil // Removal not implemented yet
}

func (h *CdxCompDescriptionHandler) Summary(selected []interface{}) {
	// cdx.RenderSummaryDescriptionFromComponents(selected)
}
