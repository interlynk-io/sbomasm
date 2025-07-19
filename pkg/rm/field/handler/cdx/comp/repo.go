package comp

import (
	cydx "github.com/CycloneDX/cyclonedx-go"
	"github.com/interlynk-io/sbomasm/pkg/rm/field/cdx"
	"github.com/interlynk-io/sbomasm/pkg/rm/types"
)

type CdxCompRepoHandler struct {
	Component *cydx.Component
}

func (h *CdxCompRepoHandler) Select(params *types.RmParams) ([]interface{}, error) {
	return cdx.SelectRepoFromComponent(h.Component)
}

func (h *CdxCompRepoHandler) Filter(selected []interface{}, params *types.RmParams) ([]interface{}, error) {
	// return cdx.FilterRepoFromComponents(selected, params)
	return nil, nil // Filtering not implemented yet
}

func (h *CdxCompRepoHandler) Remove(targets []interface{}, params *types.RmParams) error {
	// return cdx.RemoveRepoFromComponents(h.Component, targets)
	return nil // Removal not implemented yet
}

func (h *CdxCompRepoHandler) Summary(selected []interface{}) {
	// cdx.RenderSummaryRepoFromComponents(selected)
}
