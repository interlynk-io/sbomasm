package comp

// SpdxComponentAuthorHandler

import (
	"github.com/interlynk-io/sbomasm/pkg/rm/field/spdx"
	"github.com/interlynk-io/sbomasm/pkg/rm/types"
	spdxdoc "github.com/spdx/tools-golang/spdx"
)

type SpdxComponentAuthorHandler struct {
	Doc *spdxdoc.Document
}

func (h *SpdxComponentAuthorHandler) Select(params *types.RmParams) ([]interface{}, error) {
	return spdx.SelectAuthorFromComponent(h.Doc, params)
}

func (h *SpdxComponentAuthorHandler) Filter(selected []interface{}, params *types.RmParams) ([]interface{}, error) {
	return spdx.FilterAuthorFromComponent(h.Doc, selected, params)
}

func (h *SpdxComponentAuthorHandler) Remove(targets []interface{}, params *types.RmParams) error {
	return spdx.RemoveAuthorFromComponent(h.Doc, targets, params)
}

func (h *SpdxComponentAuthorHandler) Summary(selected []interface{}) {
	spdx.RenderSummaryAuthorFromComponent(selected)
}
