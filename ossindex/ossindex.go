//
// Copyright 2018-present Sonatype Inc.
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

// Definitions and functions for processing the OSS Index Feed
package ossindex

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/sonatype-nexus-community/go-sona-types/ossindex/internal/cache"
	"github.com/sonatype-nexus-community/go-sona-types/ossindex/types"
	"github.com/sonatype-nexus-community/go-sona-types/useragent"
)

const defaultOssIndexURL = "https://ossindex.sonatype.org/api/v3/component-report"

// MaxCoords is the maximum amount of coords to query OSS Index with at one time
const MaxCoords = 128

var (
	ossIndexURL string
	logLady     *logrus.Logger
)

var dbCache *cache.Cache

func init() {
	dbCache = &cache.Cache{
		DBName: "nancy-cache",
		TTL:    time.Now().Local().Add(time.Hour * 12),
	}
}

func getOssIndexURL() string {
	if ossIndexURL == "" {
		ossIndexURL = defaultOssIndexURL
	}
	return ossIndexURL
}

// RemoveCacheDirectory deletes the local database directory.
func RemoveCacheDirectory() error {
	return dbCache.RemoveCache(logLady)
}

// AuditPackagesWithOSSIndex will given a list of Package URLs, run an OSS Index audit, and takes OSS Index configuration
func AuditPackagesWithOSSIndex(purls []string, config types.Configuration, logger *logrus.Logger) ([]types.Coordinate, error) {
	return doAuditPackages(purls, &config)
}

func doAuditPackages(purls []string, config *types.Configuration) ([]types.Coordinate, error) {
	newPurls, results, err := dbCache.GetCacheValues(purls, logLady)
	if err != nil {
		return nil, &types.OSSIndexError{
			Message: "Error initializing cache",
			Err:     err,
		}
	}

	chunks := chunk(newPurls, MaxCoords)

	for _, chunk := range chunks {
		if len(chunk) > 0 {
			var request types.AuditRequest
			request.Coordinates = chunk
			logLady.WithField("request", request).Info("Prepping request to OSS Index")
			var jsonStr, _ = json.Marshal(request)

			coordinates, err := doRequestToOSSIndex(jsonStr, config)
			if err != nil {
				return nil, err
			}

			results = append(results, coordinates...)

			logLady.WithField("coordinates", coordinates).Info("Coordinates unmarshalled from OSS Index")
			err = dbCache.Insert(coordinates, logLady)
			if err != nil {
				return nil, err
			}
		}
	}
	return results, nil
}

func doRequestToOSSIndex(jsonStr []byte, config *types.Configuration) (coordinates []types.Coordinate, err error) {
	req, err := setupRequest(jsonStr, config)
	if err != nil {
		return
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return
	}

	if resp.StatusCode == http.StatusTooManyRequests {
		logLady.WithField("resp_status_code", resp.Status).Error("Error accessing OSS Index due to Rate Limiting")
		return nil, &types.OSSIndexRateLimitError{}
	}

	if resp.StatusCode != http.StatusOK {
		logLady.WithField("resp_status_code", resp.Status).Error("Error accessing OSS Index")
		return nil, &types.OSSIndexError{
			Message: fmt.Sprintf("[%s] error accessing OSS Index", resp.Status),
		}
	}

	defer func() {
		if err := resp.Body.Close(); err != nil {
			logLady.WithField("error", err).Error("Error closing response body")
		}
	}()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		logLady.WithField("error", err).Error("Error accessing OSS Index")
		return
	}

	// Process results
	if err = json.Unmarshal(body, &coordinates); err != nil {
		logLady.WithField("error", err).Error("Error unmarshalling response from OSS Index")
		return
	}
	return
}

func setupRequest(jsonStr []byte, config *types.Configuration) (req *http.Request, err error) {
	logLady.WithField("json_string", string(jsonStr)).Debug("Setting up new POST request to OSS Index")
	req, err = http.NewRequest(
		"POST",
		getOssIndexURL(),
		bytes.NewBuffer(jsonStr),
	)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", useragent.GetUserAgent(logLady, config.Version))
	req.Header.Set("Content-Type", "application/json")
	if config != nil && config.Username != "" && config.Token != "" {
		logLady.Info("Set OSS Index Basic Auth")
		req.SetBasicAuth(config.Username, config.Token)
	}

	return req, nil
}

func chunk(purls []string, chunkSize int) [][]string {
	var divided [][]string

	for i := 0; i < len(purls); i += chunkSize {
		end := i + chunkSize

		if end > len(purls) {
			end = len(purls)
		}

		divided = append(divided, purls[i:end])
	}

	return divided
}
