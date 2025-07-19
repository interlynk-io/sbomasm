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

package spdx

import (
	"fmt"
	"strings"

	"github.com/spdx/tools-golang/spdx"
)

func SelectAuthorFromMetadata(doc *spdx.Document) ([]interface{}, error) {
	if doc == nil || doc.CreationInfo == nil || len(doc.CreationInfo.Creators) == 0 {
		return nil, nil
	}

	fmt.Println("Selecting SPDX authors from CreationInfo:", doc.CreationInfo.Creators)
	var selectAuthors []interface{}
	for _, creator := range doc.CreationInfo.Creators {
		fmt.Println("Checking creator:", creator)
		if creator.CreatorType == "Person" {
			selectAuthors = append(selectAuthors, creator)
		}
	}
	fmt.Println("Selecting SPDX authors from CreationInfo:", selectAuthors)
	return selectAuthors, nil
}

func SelectLicenseFromMetadata(doc *spdx.Document) ([]interface{}, error) {
	if doc.DataLicense == "" {
		return nil, nil
	}
	fmt.Println("Selecting SPDX license from document:", doc.DataLicense)
	return []interface{}{doc.DataLicense}, nil
}

func SelectTimestampFromMetadata(doc *spdx.Document) ([]interface{}, error) {
	if doc.CreationInfo == nil || doc.CreationInfo.Created == "" {
		return nil, nil
	}

	fmt.Println("Selecting SPDX timestamp from CreationInfo:", doc.CreationInfo.Created)
	return []interface{}{doc.CreationInfo.Created}, nil
}

func SelectToolFromMetadata(doc *spdx.Document) ([]interface{}, error) {
	if doc == nil || doc.CreationInfo == nil || len(doc.CreationInfo.Creators) == 0 {
		return nil, nil
	}

	var selectTools []interface{}
	for _, creator := range doc.CreationInfo.Creators {
		if creator.CreatorType == "Tool" {
			selectTools = append(selectTools, creator)
		}
	}

	fmt.Println("Selecting SPDX tools from CreationInfo:", selectTools)
	return selectTools, nil
}

func SelectSupplierFromMetadata(doc *spdx.Document) ([]interface{}, error) {
	if doc == nil || doc.CreationInfo == nil || len(doc.CreationInfo.Creators) == 0 {
		return nil, nil
	}

	var selectSuppliers []interface{}
	for _, creator := range doc.CreationInfo.Creators {
		if creator.CreatorType == "Organization" {
			selectSuppliers = append(selectSuppliers, creator)
		}
	}
	fmt.Println("Selecting SPDX suppliers from CreationInfo:", selectSuppliers)
	return selectSuppliers, nil
}

func SelectLifecycleFromMetadata(doc *spdx.Document) ([]interface{}, error) {
	if doc == nil || doc.CreationInfo == nil {
		return nil, nil
	}

	comment := doc.CreationInfo.CreatorComment
	if strings.HasPrefix(strings.ToLower(comment), "lifecycle:") {
		fmt.Println("Selecting SPDX lifecycle from CreationInfo comment:", comment)
		return []interface{}{comment}, nil
	}

	return nil, nil
}

func SelectRepositoryFromMetadata(doc *spdx.Document) ([]interface{}, error) {
	return nil, nil // SPDX does not have a direct equivalent for repositories in metadata
}
