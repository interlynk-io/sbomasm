package comp

import (
	cydx "github.com/CycloneDX/cyclonedx-go"
	"github.com/interlynk-io/sbomasm/pkg/rm/field/cdx"
	"github.com/interlynk-io/sbomasm/pkg/rm/types"
)

type CdxCompPurlHandler struct {
	Component *cydx.Component
}

func (h *CdxCompPurlHandler) Select(params *types.RmParams) ([]interface{}, error) {
	return cdx.SelectPurlFromComponent(h.Component)
}

func (h *CdxCompPurlHandler) Filter(selected []interface{}, params *types.RmParams) ([]interface{}, error) {
	// return cdx.FilterPurlFromComponents(selected, params)
	return nil, nil // Filtering not implemented yet
}

func (h *CdxCompPurlHandler) Remove(targets []interface{}, params *types.RmParams) error {
	// return cdx.RemovePurlFromComponents(h.Component, targets)
	return nil // Removal not implemented yet
}

func (h *CdxCompPurlHandler) Summary(selected []interface{}) {
	// cdx.RenderSummaryPurlFromComponents(selected)
}
