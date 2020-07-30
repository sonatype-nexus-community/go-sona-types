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

// Package ossindex is definitions and functions for processing the OSS Index Feed
package ossindex

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"runtime"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/sonatype-nexus-community/go-sona-types/ossindex/internal/cache"
	"github.com/sonatype-nexus-community/go-sona-types/ossindex/types"
	"github.com/sonatype-nexus-community/go-sona-types/useragent"
)

const defaultOssIndexURL = "https://ossindex.sonatype.org/api/v3/component-report"

// MaxCoords is the maximum amount of coords to query OSS Index with at one time
const MaxCoords = 128

// IServer is an interface for mocking the OSS Index Server struct
type IServer interface {
	NoCacheNoProblems() error
	AuditPackages(p []string) ([]types.Coordinate, error)
}

// Server is a struct that holds the OSS Index options, logger and other properties related to
// communicating with OSS Index
type Server struct {
	Options types.Options
	logLady *logrus.Logger
	agent   *useragent.Agent
	dbCache *cache.Cache
}

// NoCacheNoProblems deletes the local database directory.
func (o *Server) NoCacheNoProblems() error {
	return o.dbCache.RemoveCache()
}

// New is intended to be the way to obtain a Server instance, where you have control of the options
func New(logger *logrus.Logger, options types.Options) *Server {
	ua := useragent.New(logger, useragent.Options{ClientTool: options.Tool, Version: options.Version, GoArch: runtime.GOARCH, GoOS: runtime.GOOS})
	return &Server{
		logLady: logger,
		Options: options,
		agent:   ua,
		dbCache: cache.New(logger, cache.Options{
			DBName: options.DBCacheName,
			TTL:    options.TTL,
		}),
	}
}

// Default is intended to be a way to obtain a Server instance, with rational defaults set
func Default(logger *logrus.Logger) *Server {
	return New(logger,
		types.Options{
			DBCacheName: "nancy-cache",
			TTL:         time.Now().Local().Add(time.Hour * 12),
		})
}

// AuditPackages will given a slice of Package URLs run an OSS Index audit, and return the result
func (o *Server) AuditPackages(purls []string) ([]types.Coordinate, error) {
	return o.doAuditPackages(purls)
}

func (o *Server) doAuditPackages(purls []string) ([]types.Coordinate, error) {
	newPurls, results, err := o.dbCache.GetCacheValues(purls)
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
			o.logLady.WithField("request", request).Info("Prepping request to OSS Index")
			var jsonStr, _ = json.Marshal(request)

			coordinates, err := o.doRequestToOSSIndex(jsonStr)
			if err != nil {
				return nil, err
			}

			results = append(results, coordinates...)

			o.logLady.WithField("coordinates", coordinates).Info("Coordinates unmarshalled from OSS Index")
			err = o.dbCache.Insert(coordinates)
			if err != nil {
				return nil, err
			}
		}
	}
	return results, nil
}

func (o *Server) doRequestToOSSIndex(jsonStr []byte) (coordinates []types.Coordinate, err error) {
	req, err := o.setupRequest(jsonStr)
	if err != nil {
		return
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return
	}

	if resp.StatusCode == http.StatusTooManyRequests {
		o.logLady.WithField("resp_status_code", resp.Status).Error("Error accessing OSS Index due to Rate Limiting")
		return nil, &types.OSSIndexRateLimitError{}
	}

	if resp.StatusCode != http.StatusOK {
		o.logLady.WithField("resp_status_code", resp.Status).Error("Error accessing OSS Index")
		return nil, &types.OSSIndexError{
			Message: fmt.Sprintf("[%s] error accessing OSS Index", resp.Status),
		}
	}

	defer func() {
		if err := resp.Body.Close(); err != nil {
			o.logLady.WithField("error", err).Error("Error closing response body")
		}
	}()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		o.logLady.WithField("error", err).Error("Error accessing OSS Index")
		return
	}

	// Process results
	if err = json.Unmarshal(body, &coordinates); err != nil {
		o.logLady.WithField("error", err).Error("Error unmarshalling response from OSS Index")
		return
	}
	return
}

func (o *Server) setupRequest(jsonStr []byte) (req *http.Request, err error) {
	o.logLady.WithField("json_string", string(jsonStr)).Debug("Setting up new POST request to OSS Index")
	req, err = http.NewRequest(
		"POST",
		o.getOssIndexURL(),
		bytes.NewBuffer(jsonStr),
	)
	if err != nil {
		return nil, err
	}

	ua := o.agent.GetUserAgent()

	req.Header.Set("User-Agent", ua)
	o.logLady.WithField("user_agent", ua).Debug("Obtained User Agent for request to OSS Index")

	req.Header.Set("Content-Type", "application/json")
	if o.Options.Username != "" && o.Options.Token != "" {
		o.logLady.Info("Set OSS Index Basic Auth")
		req.SetBasicAuth(o.Options.Username, o.Options.Token)
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

func (o *Server) getOssIndexURL() string {
	if o.Options.OSSIndexURL == "" {
		o.Options.OSSIndexURL = defaultOssIndexURL
	}
	return o.Options.OSSIndexURL
}
