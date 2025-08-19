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

package clearlydef

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/guacsec/sw-id-core/coordinates"
	"github.com/interlynk-io/sbomasm/pkg/logger"
)

const (
	API_BASE_URL             = "https://api.clearlydefined.io"
	API_BASE_DEFINITIONS_URL = API_BASE_URL + "/definitions"
)

type DefinitionResponse struct {
	Licensed struct {
		Declared string `json:"declared"`
	} `json:"licensed"`
}

func Client(ctx context.Context, coordinates map[interface{}]coordinates.Coordinate) map[interface{}]DefinitionResponse {
	log := logger.FromContext(ctx)
	log.Debug("querying clearlydefined API")

	// to keep track of path and it's responses
	cache := make(map[string]DefinitionResponse)

	// store component and it's responses
	responses := make(map[interface{}]DefinitionResponse)

	client := &http.Client{Timeout: 10 * time.Second}

	for comp, coordinate := range coordinates {
		// path := fmt.Sprintf("%s/%s/%s/%s/%s", coordinate.Type, coordinate.Provider, coordinate.Namespace, coordinate.Name, coordinate.Revision)
		path := fmt.Sprintf("%s/%s/%s/%s/%s", coordinate.CoordinateType, coordinate.Provider, coordinate.Namespace, coordinate.Name, coordinate.Revision)

		if coordinate.Namespace == "" {
			path = fmt.Sprintf("%s/%s/-/%s/%s", coordinate.CoordinateType, coordinate.Provider, coordinate.Name, coordinate.Revision)
		}

		if cached, ok := cache[path]; ok {
			responses[comp] = cached
			continue
		}

		cdURL := API_BASE_DEFINITIONS_URL + "/" + path

		if coordinate.CoordinateType == "go" {
			path = fmt.Sprintf("?coordinates=%s", url.QueryEscape(cdURL))
		}

		log.Debugf("querying clearlydefined for coordinate %s", path)
		log.Debugf("clearlydefined final URL: %s", cdURL)

		var def DefinitionResponse
		for attempt := 1; attempt <= 3; attempt++ {
			req, err := http.NewRequest("GET", cdURL, nil)
			if err != nil {
				continue
			}

			if PKG_TYPE(coordinate.CoordinateType) == "GO" {
				req.Header.Set("Accept-Version", "1.0.0")
				req.Header.Set("Content-Type", "application/json")
			}

			req.Header.Set("Accept", "*/*")

			resp, err := client.Do(req)
			if err != nil {
				continue
			}

			defer resp.Body.Close()

			if resp.StatusCode == 429 {

				// retry after reset time
				resetTime := resp.Header.Get("x-ratelimit-reset")
				log.Warnf("rate limit exceeded for %s; retrying after %s", cdURL, resetTime)

				// wait until reset time
				if resetTime != "" {
					if reset, err := strconv.ParseInt(resetTime, 10, 64); err == nil {
						time.Sleep(time.Until(time.Unix(reset, 0)))
					}
				}

				log.Infof("waiting for rate limit reset")

				continue

			} else if resp.StatusCode == 404 {
				log.Debugf("component not found for %s; queuing harvest", cdURL)
				queueHarvest(ctx, coordinate)
				continue

			} else if resp.StatusCode != 200 {
				log.Errorf("unexpected status code for %s (attempt %d/3): %d", cdURL, attempt, resp.StatusCode)

				continue
			}

			err = json.NewDecoder(resp.Body).Decode(&def)
			if err != nil {
				log.Errorf("failed to decode response for %s (attempt %d/3): %v", cdURL, attempt, err)
				continue
			}

			cache[path] = def
			responses[comp] = def
			log.Debugf("def response: %+v", def)
			break
		}
	}

	return responses
}

func queueHarvest(ctx context.Context, coordinate coordinates.Coordinate) {
	log := logger.FromContext(ctx)
	log.Debugf("queueing harvest for coordinate: %s", coordinate)

	path := fmt.Sprintf("%s/%s/%s/%s/%s", coordinate.CoordinateType, coordinate.Provider, coordinate.Namespace, coordinate.Name, coordinate.Revision)
	if coordinate.Namespace == "" {
		path = fmt.Sprintf("%s/%s/-/%s/%s", coordinate.CoordinateType, coordinate.Provider, coordinate.Name, coordinate.Revision)
	}

	payload := fmt.Sprintf(`[{"tool":"package","coordinates":"%s"}]`, path)

	req, err := http.NewRequest("POST", "https://api.clearlydefined.io/harvest", strings.NewReader(payload))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "*/*")

	client := &http.Client{Timeout: 10 * time.Second}
	_, err = client.Do(req)
	if err != nil {
		// Log error
		log.Errorf("failed to queue harvest for coordinate %s: %v", coordinate, err)
	}
}
