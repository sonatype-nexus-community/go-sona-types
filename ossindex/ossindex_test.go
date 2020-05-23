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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/shopspring/decimal"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/sonatype-nexus-community/go-sona-types/ossindex/types"
	"github.com/stretchr/testify/assert"
)

const purl = "pkg:github/BurntSushi/toml@0.3.1"

var lowerCasePurl = strings.ToLower(purl)
var expectedCoordinate types.Coordinate

func setupOptions() (options types.Options) {
	options.Username = "testuser"
	options.Token = "test"
	options.DBCacheName = "nancy-test"
	return
}

func TestOssIndexUrlDefault(t *testing.T) {
	setupTest(t)
	ossindex := setupOSSIndex(t)
	assert.Equal(t, defaultOssIndexURL, ossindex.getOssIndexURL())
}

func TestAuditPackages_Empty(t *testing.T) {
	setupTest(t)
	ossindex := setupOSSIndex(t)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("No call should occur with empty package. called: %v", r)
	}))
	defer ts.Close()
	ossindex.Options.OSSIndexURL = ts.URL

	coordinates, err := ossindex.AuditPackages([]string{})
	assert.Equal(t, []types.Coordinate(nil), coordinates)
	assert.Nil(t, err)
}

func TestAuditPackages_Nil(t *testing.T) {
	setupTest(t)
	ossindex := setupOSSIndex(t)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("No call should occur with nil package. called: %v", r)
	}))
	defer ts.Close()
	ossindex.Options.OSSIndexURL = ts.URL

	coordinates, err := ossindex.AuditPackages(nil)
	assert.Equal(t, []types.Coordinate(nil), coordinates)
	assert.Nil(t, err)
}

func TestAuditPackages_ErrorHttpRequest(t *testing.T) {
	setupTest(t)
	ossindex := setupOSSIndex(t)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("No call should occur with nil package. called: %v", r)
	}))
	defer ts.Close()
	ossindex.Options.OSSIndexURL = ts.URL + "\\"

	coordinates, err := ossindex.AuditPackages([]string{"nonexistent-purl"})
	assert.Equal(t, []types.Coordinate(nil), coordinates)
	parseError := err.(*url.Error)
	assert.Equal(t, "parse", parseError.Op)
}

func TestAuditPackages_ErrorNonExistentPurl(t *testing.T) {
	setupTest(t)
	ossindex := setupOSSIndex(t)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/", r.URL.EscapedPath())

		w.WriteHeader(http.StatusBadRequest)
	}))
	defer ts.Close()
	ossindex.Options.OSSIndexURL = ts.URL

	coordinates, err := ossindex.AuditPackages([]string{"nonexistent-purl"})
	assert.Equal(t, []types.Coordinate(nil), coordinates)
	assert.Equal(t, "An error occurred: [400 Bad Request] error accessing OSS Index", err.Error())
}

func TestAuditPackages_ErrorBadResponseBody(t *testing.T) {
	setupTest(t)
	ossindex := setupOSSIndex(t)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/", r.URL.EscapedPath())

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("badStuff"))
	}))
	defer ts.Close()
	ossindex.Options.OSSIndexURL = ts.URL

	coordinates, err := ossindex.AuditPackages([]string{purl})

	assert.Equal(t, []types.Coordinate(nil), coordinates)
	jsonError := err.(*json.SyntaxError)
	assert.Equal(t, int64(1), jsonError.Offset)
	assert.Equal(t, "invalid character 'b' looking for beginning of value", jsonError.Error())
}

func TestAuditPackages_NewPackage(t *testing.T) {
	setupTest(t)
	ossindex := setupOSSIndex(t)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		verifyClientCallAndWriteValidPackageResponse(t, r, w)
	}))
	defer ts.Close()
	ossindex.Options.OSSIndexURL = ts.URL

	coordinates, err := ossindex.AuditPackages([]string{purl})

	assert.Equal(t, []types.Coordinate{expectedCoordinate}, coordinates)
	assert.Nil(t, err)
}

func verifyClientCallAndWriteValidPackageResponse(t *testing.T, r *http.Request, w http.ResponseWriter) {
	assert.Equal(t, http.MethodPost, r.Method)
	assert.Equal(t, "/", r.URL.EscapedPath())
	w.WriteHeader(http.StatusOK)
	coordinates := []types.Coordinate{expectedCoordinate}
	jsonCoordinates, _ := json.Marshal(coordinates)
	_, _ = w.Write(jsonCoordinates)
}

func TestAuditPackages_SinglePackage_Cached(t *testing.T) {
	setupTest(t)
	ossindex := setupOSSIndex(t)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("No call should occur with previously cached package. called: %v", r)
	}))
	defer ts.Close()
	ossindex.Options.OSSIndexURL = ts.URL

	var tempCoordinates []types.Coordinate
	tempCoordinates = append(tempCoordinates, expectedCoordinate)

	err := ossindex.dbCache.Insert(tempCoordinates)
	if err != nil {
		t.Error(err)
	}

	coordinates, err := ossindex.AuditPackages([]string{purl})
	assert.Equal(t, []types.Coordinate{expectedCoordinate}, coordinates)
	assert.Nil(t, err)
}

func TestAuditPackages_SinglePackage_Cached_WithExpiredTTL(t *testing.T) {
	setupTest(t)
	ossindex := setupOSSIndex(t)

	// Set the cache TTL to a date in the past for testing
	ossindex.dbCache.Options.TTL = time.Now().AddDate(0, 0, -1)

	var tempCoordinates []types.Coordinate
	tempCoordinates = append(tempCoordinates, expectedCoordinate)

	err := ossindex.dbCache.Insert(tempCoordinates)
	if err != nil {
		t.Error(err)
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		verifyClientCallAndWriteValidPackageResponse(t, r, w)
	}))
	defer ts.Close()
	ossindex.Options.OSSIndexURL = ts.URL

	coordinates, err := ossindex.AuditPackages([]string{purl})
	assert.Equal(t, []types.Coordinate{expectedCoordinate}, coordinates)
	assert.Nil(t, err)
}

func setupOSSIndex(t *testing.T) *OSSIndex {
	logger, _ := test.NewNullLogger()
	ossindex := New(logger, setupOptions())
	err := ossindex.dbCache.RemoveCache()
	if err != nil {
		t.Error(err)
	}
	return ossindex
}

func setupTest(t *testing.T) {
	dec, _ := decimal.NewFromString("9.8")
	expectedCoordinate = types.Coordinate{
		Coordinates: lowerCasePurl,
		Reference:   "https://ossindex.sonatype.org/component/" + lowerCasePurl,
		Vulnerabilities: []types.Vulnerability{
			{
				ID:          "id",
				Title:       "test",
				Description: "description",
				CvssScore:   dec,
				CvssVector:  "vectorvictor",
				Cve:         "CVE-123-123",
				Reference:   "http://www.internet.com",
				Excluded:    false,
			},
		},
	}
}

func TestSetupRequest(t *testing.T) {
	coordJSON, _ := setupJSON(t)
	ossindex := setupOSSIndex(t)
	req, err := ossindex.setupRequest(coordJSON)

	assert.Equal(t, req.Header.Get("Content-Type"), "application/json")
	assert.Equal(t, req.Method, "POST")
	user, token, ok := req.BasicAuth()
	assert.Equal(t, user, "testuser")
	assert.Equal(t, token, "test")
	assert.Equal(t, ok, true)
	assert.Nil(t, err)
}

// TODO: Use this for more than just TestSetupRequest
func setupJSON(t *testing.T) (coordJSON []byte, err error) {
	coordJSON, err = json.Marshal(expectedCoordinate)
	if err != nil {
		t.Errorf("Couldn't setup json")
	}

	return
}
