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

package edit

import (
	"errors"
	"os"
	"time"

	"github.com/interlynk-io/sbomasm/pkg/detect"
)

var errNoConfiguration = errors.New("no configuration provided")
var errNotSupported = errors.New("not supported")
var errInvalidInput = errors.New("invalid input data")

func detectSbom(path string) (string, string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", "", err
	}
	defer f.Close()

	spec, format, err := detect.Detect(f)
	if err != nil {
		return "", "", err
	}
	return string(spec), string(format), nil
}

func utcNowTime() string {
	location, _ := time.LoadLocation("UTC")
	locationTime := time.Now().In(location)
	return locationTime.Format(time.RFC3339)
}
