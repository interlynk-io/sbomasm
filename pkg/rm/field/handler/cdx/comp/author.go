package comp

import (
	cydx "github.com/CycloneDX/cyclonedx-go"
	"github.com/interlynk-io/sbomasm/pkg/rm/field/cdx"
	"github.com/interlynk-io/sbomasm/pkg/rm/types"
)

type CdxCompAuthorHandler struct {
	Component *cydx.Component
}

func (h *CdxCompAuthorHandler) Select(params *types.RmParams) ([]interface{}, error) {
	return cdx.SelectAuthorFromComponents(h.Component)
}

func (h *CdxCompAuthorHandler) Filter(selected []interface{}, params *types.RmParams) ([]interface{}, error) {
	// return cdx.FilterAuthorFromComponents(selected, params)
	return nil, nil // Filtering not implemented yet
}

func (h *CdxCompAuthorHandler) Remove(targets []interface{}, params *types.RmParams) error {
	// return cdx.RemoveAuthorFromComponents(h.Bom, targets)
	return nil // Removal not implemented yet
}

func (h *CdxCompAuthorHandler) Summary(selected []interface{}) {
	// cdx.RenderSummaryAuthorFromComponents(selected)
}
