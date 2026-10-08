// Copyright 2025 Interlynk.io
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package rm

import (
	"bytes"
	"context"
	"sync"
	"testing"

	"github.com/interlynk-io/sbomasm/v2/pkg/logger"
	"github.com/interlynk-io/sbomasm/v2/pkg/rm/types"
	"github.com/interlynk-io/spdx-zen/parse"
)

var initLoggerOnce sync.Once

// parseSpdx3FromBytes parses an SPDX 3.0 JSON-LD document from bytes.
func parseSpdx3FromBytes(t *testing.T, data []byte) *parse.Document {
	t.Helper()
	doc, err := parse.NewReader().FromReader(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("failed to parse SPDX 3.0 from bytes: %v", err)
	}
	return doc
}

// newRmParams creates RmParams with a context for testing.
func newRmParams(t *testing.T) *types.RmParams {
	t.Helper()
	initLoggerOnce.Do(func() {
		logger.InitProdLogger()
	})
	ctx := logger.WithLogger(context.Background())
	return &types.RmParams{
		Ctx: &ctx,
	}
}
