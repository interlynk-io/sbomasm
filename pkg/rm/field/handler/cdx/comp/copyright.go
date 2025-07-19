package comp

import (
	cydx "github.com/CycloneDX/cyclonedx-go"
	"github.com/interlynk-io/sbomasm/pkg/rm/field/cdx"
	"github.com/interlynk-io/sbomasm/pkg/rm/types"
)

type CdxCompCopyrightHandler struct {
	Component *cydx.Component
}

func (h *CdxCompCopyrightHandler) Select(params *types.RmParams) ([]interface{}, error) {
	return cdx.SelectCopyrightFromComponents(h.Component)
}

func (h *CdxCompCopyrightHandler) Filter(selected []interface{}, params *types.RmParams) ([]interface{}, error) {
	// return cdx.FilterCopyrightFromComponents(selected, params)
	return nil, nil // Filtering not implemented yet
}

func (h *CdxCompCopyrightHandler) Remove(targets []interface{}, params *types.RmParams) error {
	// return cdx.RemoveCopyrightFromComponents(h.Bom, targets)
	return nil // Removal not implemented yet
}

func (h *CdxCompCopyrightHandler) Summary(selected []interface{}) {
	// cdx.RenderSummaryCopyrightFromComponents(selected)
}
