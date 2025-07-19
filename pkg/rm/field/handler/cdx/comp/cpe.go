package comp

import (
	cydx "github.com/CycloneDX/cyclonedx-go"
	"github.com/interlynk-io/sbomasm/pkg/rm/field/cdx"
	"github.com/interlynk-io/sbomasm/pkg/rm/types"
)

type CdxCompCPEHandler struct {
	Component *cydx.Component
}

func (h *CdxCompCPEHandler) Select(params *types.RmParams) ([]interface{}, error) {
	return cdx.SelectCPEFromComponent(h.Component)
}

func (h *CdxCompCPEHandler) Filter(selected []interface{}, params *types.RmParams) ([]interface{}, error) {
	// return cdx.FilterCPEFromComponents(selected, params)
	return nil, nil // Filtering not implemented yet
}

func (h *CdxCompCPEHandler) Remove(targets []interface{}, params *types.RmParams) error {
	// return cdx.RemoveCPEFromComponents(h.Bom, targets)
	return nil // Removal not implemented yet
}

func (h *CdxCompCPEHandler) Summary(selected []interface{}) {
	// cdx.RenderSummaryCPEFromComponents(selected)
}
