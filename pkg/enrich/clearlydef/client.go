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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/cheggaaa/pb/v3"
	"github.com/guacsec/sw-id-core/coordinates"
	"github.com/hashicorp/go-retryablehttp"
	"github.com/interlynk-io/sbomasm/pkg/logger"
	"golang.org/x/time/rate"
)

const (
	API_BASE_URL             = "https://api.clearlydefined.io"
	API_BASE_DEFINITIONS_URL = API_BASE_URL + "/definitions"
	API_BASE_HARVEST_URL     = API_BASE_URL + "/harvest"
)

type transport struct {
	Wrapped http.RoundTripper
	RL      *rate.Limiter
}

func (t *transport) RoundTrip(r *http.Request) (*http.Response, error) {
	if err := t.RL.Wait(r.Context()); err != nil {
		return nil, err
	}
	return t.Wrapped.RoundTrip(r)
}

// DefinitionResponse represents the ClearlyDefined API response
type DefinitionResponse struct {
	Licensed struct {
		Declared string `json:"declared"`
	} `json:"licensed"`
}

func NewRetryableClient(ctx context.Context, maxRetries int, maxWait time.Duration) *retryablehttp.Client {
	log := logger.FromContext(ctx)

	retryClient := retryablehttp.NewClient()
	retryClient.RetryMax = maxRetries
	retryClient.RetryWaitMax = maxWait

	// custom logger
	rcLogger := &logger.ZapRetryLogger{Debug: true, Logger: log}
	retryClient.Logger = rcLogger

	// custom transport with rate limiter
	transport := &transport{
		Wrapped: http.DefaultTransport,
		RL:      rate.NewLimiter(rate.Every(time.Minute), 250),
	}
	retryClient.HTTPClient.Transport = transport

	return retryClient
}

// Client queries the ClearlyDefined API for license data
func Client(ctx context.Context, componentsToCoordinateMappings map[interface{}]coordinates.Coordinate, maxRetries int, maxWait time.Duration, chunkSize int) (map[interface{}]DefinitionResponse, error) {
	log := logger.FromContext(ctx)
	log.Debug("querying clearlydefined API")

	responses := make(map[interface{}]DefinitionResponse)
	coordList := []string{}
	coordToComp := make(map[string]interface{})

	retryClient := NewRetryableClient(ctx, maxRetries, maxWait)

	// Map coordinates into a single POST request
	for comp, coordinate := range componentsToCoordinateMappings {
		coordinatePath := constructPathFromCoordinate(coordinate)
		coordList = append(coordList, coordinatePath)
		coordToComp[coordinatePath] = comp
	}

	if len(coordList) == 0 {
		fmt.Println("No coordinates to query, coordinate list is empty.")
		return nil, nil
	}

	fmt.Printf("\nFetching Components Response...\n")
	bar := pb.StartNew(len(coordList))

	log.Debugf("querying %d coordinates", len(coordList))
	log.Debugf("list of coordinates: %v", coordList)

	// Process coordinates in chunks
	for i := 0; i < len(coordList); i += chunkSize {
		if err := ctx.Err(); err != nil {
			return responses, err
		}

		end := i + chunkSize

		if end >= len(coordList) {
			end = len(coordList)
		}
		bar.SetCurrent(int64(end))
		chunk := coordList[i:end]

		// POST request for the chunk
		cs, err := json.Marshal(chunk)
		if err != nil {
			fmt.Printf("Error marshalling coordinates: %v\n", err)
			continue
		}

		req, err := retryablehttp.NewRequestWithContext(ctx, "POST", API_BASE_DEFINITIONS_URL, bytes.NewBuffer(cs))
		if err != nil {
			log.Debugf("Error creating POST request: %v", err)
			continue
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := retryClient.Do(req)
		if err != nil {
			log.Debugf("Error querying ClearlyDefined: %v", err)
			continue
		}

		if resp.StatusCode != http.StatusOK {
			log.Debugf("Unexpected status code from ClearlyDefined: %d", resp.StatusCode)
			continue
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			log.Debugf("Error reading response body: %v", err)
			continue
		}

		var defs map[string]DefinitionResponse
		if err := json.Unmarshal(body, &defs); err != nil {
			log.Debugf("Error unmarshalling JSON: %v", err)
			continue
		}

		// Map responses back to components
		for coord, def := range defs {
			if comp, ok := coordToComp[coord]; ok {
				if def.Licensed.Declared == "" {
					err = queueHarvest(ctx, retryClient, componentsToCoordinateMappings[comp])
					if err != nil {
						log.Debugf("failed to queue harvest for %s: %v", coord, err)
					}
				} else {
					responses[comp] = def
				}
			}
		}
	}
	bar.Finish()

	return responses, nil
}

func constructPathFromCoordinate(coordinate coordinates.Coordinate) string {
	path := fmt.Sprintf("%s/%s/%s/%s/%s", coordinate.CoordinateType, coordinate.Provider, coordinate.Namespace, coordinate.Name, coordinate.Revision)
	if coordinate.Namespace == "" {
		path = fmt.Sprintf("%s/%s/-/%s/%s", coordinate.CoordinateType, coordinate.Provider, coordinate.Name, coordinate.Revision)
	}
	return path
}

func queueHarvest(ctx context.Context, retryClient *retryablehttp.Client, coordinate coordinates.Coordinate) error {
	path := constructPathFromCoordinate(coordinate)
	if path == "" {
		return fmt.Errorf("invalid coordinate for harvest: %+v", coordinate)
	}

	payload := []struct {
		Tool        string `json:"tool"`
		Coordinates string `json:"coordinates"`
	}{
		{
			Tool:        "package",
			Coordinates: path,
		},
	}

	cs, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("error marshalling harvest payload: %w", err)
	}

	req, err := retryablehttp.NewRequestWithContext(ctx, "POST", API_BASE_HARVEST_URL, bytes.NewBuffer(cs))
	if err != nil {
		return fmt.Errorf("error creating harvest request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "*/*")

	resp, err := retryClient.Do(req)
	if err != nil {
		return fmt.Errorf("error sending harvest request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("unexpected status code for harvest: %d", resp.StatusCode)
	}

	fmt.Printf("Successfully queued harvest for %s\n", coordinate)

	return nil
}
