package comp

import (
	cydx "github.com/CycloneDX/cyclonedx-go"
	"github.com/interlynk-io/sbomasm/pkg/rm/field/cdx"
	"github.com/interlynk-io/sbomasm/pkg/rm/types"
)

type CdxCompSupplierHandler struct {
	Component *cydx.Component
}

func (h *CdxCompSupplierHandler) Select(params *types.RmParams) ([]interface{}, error) {
	return cdx.SelectSupplierFromComponent(h.Component)
}

func (h *CdxCompSupplierHandler) Filter(selected []interface{}, params *types.RmParams) ([]interface{}, error) {
	// return cdx.FilterSupplierFromComponents(selected, params)
	return nil, nil // Filtering not implemented yet
}

func (h *CdxCompSupplierHandler) Remove(targets []interface{}, params *types.RmParams) error {
	// return cdx.RemoveSupplierFromComponents(h.Component, targets)
	return nil // Removal not implemented yet
}

func (h *CdxCompSupplierHandler) Summary(selected []interface{}) {
	// cdx.RenderSummarySupplierFromComponents(selected)
}
