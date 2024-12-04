// Copyright 2023 Interlynk.io
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
//

package cdx

import (
	"context"
	"fmt"
	"strings"

	cydx "github.com/CycloneDX/cyclonedx-go"
)

type uniqueComponentService struct {
	ctx context.Context
	// unique list of new components
	compMap map[string]*cydx.Component

	// mapping from old component id to new component id
	idMap map[string]string
}

func newUniqueComponentService(ctx context.Context) *uniqueComponentService {
	return &uniqueComponentService{
		ctx:     ctx,
		compMap: make(map[string]*cydx.Component),
		idMap:   make(map[string]string),
	}
}

func (s *uniqueComponentService) StoreAndCloneWithNewID(c *cydx.Component) (*cydx.Component, bool) {
	if c == nil {
		return nil, false
	}

	lookupKey := fmt.Sprintf("%s-%s-%s",
		strings.ToLower(string(c.Type)),
		strings.ToLower(c.Name),
		strings.ToLower(c.Version))

	if foundComp, ok := s.compMap[lookupKey]; ok {
		if c.BOMRef != foundComp.BOMRef {
			s.idMap[c.BOMRef] = foundComp.BOMRef
		}
		return foundComp, true
	}

	nc, err := cloneComp(c)
	if err != nil {
		panic(err)
	}

	newID := newBomRef()
	nc.BOMRef = newID

	s.compMap[lookupKey] = nc
	s.idMap[c.BOMRef] = newID
	return nc, false
}

func (s *uniqueComponentService) ResolveDepID(depID string) (string, bool) {
	if newID, ok := s.idMap[depID]; ok {
		return newID, true
	}
	return "", false
}

func (s *uniqueComponentService) ResolveDepIDs(depIDs []string) []string {
	ids := make([]string, 0, len(depIDs))
	for _, depID := range depIDs {
		if newID, ok := s.idMap[depID]; ok {
			ids = append(ids, newID)
		}
	}
	return ids
}
