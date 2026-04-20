// Copyright 2026 Interlynk.io
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package gsbom

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Supported hash algorithms
var supportedHashAlgorithms = map[string]bool{
	"SHA-256": true,
	"SHA-512": true,
}

// ComputeHashes performs the following functionality:
// - Iterates through all components and their specified hashes.
// - For each hash that specifies a file or path (instead of a literal value), it computes the hash value from disk.
// - It supports both file-based hashes (hash of a single file) and path-based hashes (hash of all files under a directory).
// - It updates the component's hash entries with the computed hash values.
// - It collects and returns any errors encountered during the hashing process.
func ComputeHashes(components []Component, manifestDir string) []error {
	var errors []error

	for i := range components {
		comp := &components[i]
		for j := range comp.Hashes {
			h := &comp.Hashes[j]

			// 1. Literal method: Skip if value is already provided
			if h.Value != "" {
				continue
			}

			// Validate algorithm(ONLY SHA-256, SHA-512 supported for now)
			algo := strings.ToUpper(strings.TrimSpace(h.Algorithm))
			if !supportedHashAlgorithms[algo] {
				errors = append(errors, fmt.Errorf("component %s@%s: unsupported hash algorithm '%s'", comp.Name, comp.Version, h.Algorithm))
				continue
			}

			// 2. File hash: Compute based on file or path
			if h.File != "" {
				value, err := computeFileHash(filepath.Join(manifestDir, h.File), algo)
				if err != nil {
					errors = append(errors, fmt.Errorf("component %s@%s: failed to hash file '%s': %w", comp.Name, comp.Version, h.File, err))
					continue
				}
				h.Value = value
			} else if h.Path != "" {

				// 3. Dir Hash: Compute based on directory (with optional extensions filter)
				value, err := computeDirectoryHash(filepath.Join(manifestDir, h.Path), h.Extensions, algo)
				if err != nil {
					errors = append(errors, fmt.Errorf("component %s@%s: failed to hash directory '%s': %w", comp.Name, comp.Version, h.Path, err))
					continue
				}
				h.Value = value
			}
		}
	}

	return errors
}

// computeFileHash computes the hash of a single file.
func computeFileHash(path string, algorithm string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return "", fmt.Errorf("failed to stat file: %w", err)
	}

	if info.IsDir() {
		return "", fmt.Errorf("'file' hash target is a directory, use 'path' for directories: %s", path)
	}

	hsh := newHash(algorithm)
	if _, err := io.Copy(hsh, file); err != nil {
		return "", fmt.Errorf("failed to hash file: %w", err)
	}

	digest := hsh.Sum(nil)
	return hex.EncodeToString(digest), nil
}

// computeDirectoryHash computes a deterministic hash of all matching files under a directory.
// It walks the directory recursively, filters by extensions (if provided), excludes hidden files,
// and produces a sorted manifest that is then hashed.
func computeDirectoryHash(rootPath string, extensions []string, algorithm string) (string, error) {
	info, err := os.Stat(rootPath)
	if err != nil {
		return "", fmt.Errorf("failed to stat path: %w", err)
	}

	// If path is a single file, treat it like file hash
	if !info.IsDir() {
		return computeFileHash(rootPath, algorithm)
	}

	// Normalize extensions (remove leading dots and wildcards)
	extFilter := make(map[string]bool)
	for _, ext := range extensions {
		ext := normalizeExt(ext)
		if ext != "" {
			extFilter[ext] = true
		}
	}

	var fileEntries []fileEntry

	err = filepath.Walk(rootPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			// Log warning for symlink issues but continue
			return nil
		}

		// Skip hidden directories (starting with .)
		if info.IsDir() {
			// Validation Rules: (SKIP Silently)
			if strings.HasPrefix(info.Name(), ".") && info.Name() != "." {
				return filepath.SkipDir
			}
			return nil
		}

		// Skip hidden files
		if strings.HasPrefix(info.Name(), ".") {
			return nil
		}

		// Skip symlinks
		// Validation Rules: (SKIP + WARN))
		if info.Mode()&os.ModeSymlink != 0 {
			return nil
		}

		// Apply extension filter if specified
		if len(extFilter) > 0 {
			ext := normalizeExt(filepath.Ext(info.Name()))

			// If filter exists, only include matching extensions
			if len(extFilter) > 0 {
				if ext == "" {
					return nil
				}
				if !extFilter[ext] {
					return nil
				}
			}
		}

		// Compute hash for this file
		fileHash, err := computeFileHash(path, algorithm)
		if err != nil {
			return err
		}

		// Get relative path from root
		relPath, err := filepath.Rel(rootPath, path)
		if err != nil {
			return err
		}

		// Normalize to forward slashes for determinism
		relPath = filepath.ToSlash(relPath)

		fileEntries = append(fileEntries, fileEntry{
			path: relPath,
			hash: fileHash,
		})

		return nil
	})

	if err != nil {
		return "", err
	}

	if len(fileEntries) == 0 {
		return "", fmt.Errorf("no matching files found in directory: %s", rootPath)
	}

	// Sort by relative path for determinism
	sort.Slice(fileEntries, func(i, j int) bool {
		return fileEntries[i].path < fileEntries[j].path
	})

	// Build manifest: "<hash>  <path>\n" for each file
	var manifest strings.Builder
	for _, entry := range fileEntries {
		manifest.WriteString(entry.hash)
		manifest.WriteString("  ")
		manifest.WriteString(entry.path)
		manifest.WriteString("\n")
	}

	// Hash the manifest
	h := newHash(algorithm)
	h.Write([]byte(manifest.String()))

	return hex.EncodeToString(h.Sum(nil)), nil
}

// normalizeExt normalizes an extension by removing
// leading dots and wildcards, and converting to lowercase.
func normalizeExt(ext string) string {
	ext = strings.TrimSpace(ext)

	// Remove "*." first
	ext = strings.TrimPrefix(ext, "*.")

	// Then remove "." if still present
	ext = strings.TrimPrefix(ext, ".")

	return strings.ToLower(ext)
}

// fileEntry represents a file with its relative path and hash
type fileEntry struct {
	path string
	hash string
}

// newHash creates a new hash.Hash based on the algorithm name.
func newHash(algorithm string) hash.Hash {
	switch strings.ToUpper(strings.TrimSpace(algorithm)) {
	case "SHA-256":
		return sha256.New()
	case "SHA-512":
		return sha512.New()
	default:
		// Default to SHA-256
		return sha256.New()
	}
}
