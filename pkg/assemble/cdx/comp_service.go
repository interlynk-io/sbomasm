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

package cdx

import (
	"context"

	cydx "github.com/CycloneDX/cyclonedx-go"
	"github.com/interlynk-io/sbomasm/pkg/logger"
)

type item struct {
	comp  *cydx.Component
	oldID string
	newID string
}

type idmap struct {
	oldID string
	newID string
}

type ComponentService struct {
	ctx    context.Context
	idList []idmap
}

func newComponentService(ctx context.Context) *ComponentService {
	return &ComponentService{
		ctx:    ctx,
		idList: []idmap{},
	}
}

func (s *ComponentService) StoreAndCloneWithNewID(c *cydx.Component) *cydx.Component {
	//log := logger.FromContext(s.ctx)
	if c == nil {
		return nil
	}

	nc, err := cloneComp(c)
	if err != nil {
		panic(err)
	}

	newID := newBomRef(nc)
	nc.BOMRef = newID

	s.idList = append(s.idList, idmap{
		oldID: c.BOMRef,
		newID: newID,
	})

	return nc
}

func (s *ComponentService) ResolveDepID(depID string) (string, bool) {
	for _, v := range s.idList {
		if v.oldID == depID {
			return v.newID, true
		}
	}
	return "", false
}

func (s *ComponentService) ResolveDepIDs(depIDs []string) []string {
	ids := []string{}
	for _, depID := range depIDs {
		if id, ok := s.ResolveDepID(depID); ok {
			ids = append(ids, id)
		}
	}
	return ids
}

func (s *ComponentService) Dump() {
	log := logger.FromContext(s.ctx)
	for _, v := range s.idList {
		log.Debugf("%s %s", v.newID, v.oldID)
	}
}
