package comp

import (
	cydx "github.com/CycloneDX/cyclonedx-go"
	"github.com/interlynk-io/sbomasm/pkg/rm/field/cdx"
	"github.com/interlynk-io/sbomasm/pkg/rm/types"
)

type CdxCompHashHandler struct {
	Component *cydx.Component
}

func (h *CdxCompHashHandler) Select(params *types.RmParams) ([]interface{}, error) {
	return cdx.SelectHashFromComponent(h.Component)
}

func (h *CdxCompHashHandler) Filter(selected []interface{}, params *types.RmParams) ([]interface{}, error) {
	// return cdx.FilterHashFromComponents(selected, params)
	return nil, nil // Filtering not implemented yet
}

func (h *CdxCompHashHandler) Remove(targets []interface{}, params *types.RmParams) error {
	// return cdx.RemoveHashFromComponents(h.Component, targets)
	return nil // Removal not implemented yet
}

func (h *CdxCompHashHandler) Summary(selected []interface{}) {
	// cdx.RenderSummaryHashFromComponents(selected)
}
