package comp

import (
	cydx "github.com/CycloneDX/cyclonedx-go"
	"github.com/interlynk-io/sbomasm/pkg/rm/field/cdx"
	"github.com/interlynk-io/sbomasm/pkg/rm/types"
)

type CdxCompLicenseHandler struct {
	Component *cydx.Component
}

func (h *CdxCompLicenseHandler) Select(params *types.RmParams) ([]interface{}, error) {
	return cdx.SelectLicenseFromComponent(h.Component)
}

func (h *CdxCompLicenseHandler) Filter(selected []interface{}, params *types.RmParams) ([]interface{}, error) {
	// return cdx.FilterLicenseFromComponents(selected, params)
	return nil, nil // Filtering not implemented yet
}

func (h *CdxCompLicenseHandler) Remove(targets []interface{}, params *types.RmParams) error {
	// return cdx.RemoveLicenseFromComponents(h.Component, targets)
	return nil // Removal not implemented yet
}

func (h *CdxCompLicenseHandler) Summary(selected []interface{}) {
	// cdx.RenderSummaryLicenseFromComponents(selected)
}
