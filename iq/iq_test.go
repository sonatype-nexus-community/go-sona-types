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

// Package iq has definitions and functions for processing golang purls with Nexus IQ Server
package iq

import (
	"encoding/json"
	"github.com/sonatype-nexus-community/go-sona-types/ossindex"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jarcoal/httpmock"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/sonatype-nexus-community/go-sona-types/ossindex/types"
	"github.com/stretchr/testify/assert"
)

const applicationsResponse = `{
	"applications": [
		{
			"id": "4bb67dcfc86344e3a483832f8c496419",
			"publicId": "testapp",
			"name": "TestApp",
			"organizationId": "bb41817bd3e2403a8a52fe8bcd8fe25a",
			"contactUserName": "NewAppContact",
			"applicationTags": [
				{
					"id": "9beee80c6fc148dfa51e8b0359ee4d4e",
					"tagId": "cfea8fa79df64283bd64e5b6b624ba48",
					"applicationId": "4bb67dcfc86344e3a483832f8c496419"
				}
			]
		}
	]
}`

const thirdPartyAPIResultJSON = `{
		"statusUrl": "api/v2/scan/applications/4bb67dcfc86344e3a483832f8c496419/status/9cee2b6366fc4d328edc318eae46b2cb"
}`

const pollingResult = `{
	"policyAction": "None",
	"reportHtmlUrl": "http://sillyplace.com:8090/ui/links/application/test-app/report/95c4c14e",
	"isError": false
}`

func setupIqOptions() (options Options) {
	options.Application = "testapp"
	options.Server = "http://sillyplace.com:8090"
	options.Stage = "develop"
	options.User = "admin"
	options.Token = "admin123"
	options.Tool = "iq-client"
	options.Version = "development"
	options.DBCacheName = "nancy-iq-test"
	options.TTL = time.Now().Local().Add(time.Hour * 12)
	options.MaxRetries = 1
	return
}

func TestAuditPackages(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	jsonCoordinates, _ := json.Marshal([]types.Coordinate{
		{
			Coordinates:     "pkg:golang/golang.org/x/crypto@v0.0.0-20190308221718-c2843e01d9a2",
			Reference:       "https://ossindex.sonatype.org/component/pkg:golang/golang.org/x/crypto@v0.0.0-20190308221718-c2843e01d9a2",
			Vulnerabilities: []types.Vulnerability{},
		},
		{
			Coordinates:     "pkg:golang/github.com/go-yaml/yaml@v2.2.2",
			Reference:       "https://ossindex.sonatype.org/component/pkg:golang/github.com/go-yaml/yaml@v2.2.2",
			Vulnerabilities: []types.Vulnerability{},
		},
	})

	httpmock.RegisterResponder("POST", "https://ossindex.sonatype.org/api/v3/component-report",
		httpmock.NewStringResponder(200, string(jsonCoordinates)))

	httpmock.RegisterResponder("GET", "http://sillyplace.com:8090/api/v2/applications?publicId=testapp",
		httpmock.NewStringResponder(200, applicationsResponse))

	httpmock.RegisterResponder("POST", "http://sillyplace.com:8090/api/v2/scan/applications/4bb67dcfc86344e3a483832f8c496419/sources/nancy?stageId=develop",
		httpmock.NewStringResponder(202, thirdPartyAPIResultJSON))

	httpmock.RegisterResponder("GET", "http://sillyplace.com:8090/api/v2/scan/applications/4bb67dcfc86344e3a483832f8c496419/status/9cee2b6366fc4d328edc318eae46b2cb",
		httpmock.NewStringResponder(200, pollingResult))

	var purls []string
	purls = append(purls, "pkg:golang/github.com/go-yaml/yaml@v2.2.2")
	purls = append(purls, "pkg:golang/golang.org/x/crypto@v0.0.0-20190308221718-c2843e01d9a2")

	iq := setupIQServer()

	result, _ := iq.AuditPackages(purls)

	statusExpected := StatusURLResult{PolicyAction: "None", ReportHTMLURL: "http://sillyplace.com:8090/ui/links/application/test-app/report/95c4c14e", IsError: false}

	assert.Equal(t, result, statusExpected)
}

func TestAuditPackagesIqCannotLocateApplicationID(t *testing.T) {
	expectedError := "An error occurred: Unable to retrieve an internal ID, err: Unable to retrieve an internal ID for the specified public application ID: testapp"
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	httpmock.RegisterResponder("GET", "http://sillyplace.com:8090/api/v2/applications?publicId=testapp",
		httpmock.NewBytesResponder(200, []byte(`{ "applications": [] }`)))

	var purls []string
	purls = append(purls, "pkg:golang/github.com/go-yaml/yaml@v2.2.2")
	purls = append(purls, "pkg:golang/golang.org/x/crypto@v0.0.0-20190308221718-c2843e01d9a2")

	iq := setupIQServer()

	_, err := iq.AuditPackages(purls)
	if err == nil {
		t.Errorf("err should not be nil, expected an err with the following text: %s", expectedError)
	}
	if err.Error() != expectedError {
		t.Errorf("Error returned is not as expected. Expected: %s but got: %s", expectedError, err.Error())
	}
}

func TestAuditPackagesIqInvalidLicense(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	httpmock.RegisterResponder("GET", "http://sillyplace.com:8090/api/v2/applications?publicId=testapp",
		httpmock.NewBytesResponder(http.StatusPaymentRequired, []byte{}))

	var purls []string
	purls = append(purls, "pkg:golang/github.com/go-yaml/yaml@v2.2.2")
	purls = append(purls, "pkg:golang/golang.org/x/crypto@v0.0.0-20190308221718-c2843e01d9a2")

	iq := setupIQServer()

	_, err := iq.AuditPackages(purls)
	assert.Error(t, err)
	_, ok := err.(*ServerErrorMissingLicense)
	assert.True(t, ok)
}

func TestAuditPackagesIqDownOrUnreachable(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	jsonCoordinates, _ := json.Marshal([]types.Coordinate{
		{
			Coordinates:     "pkg:golang/golang.org/x/crypto@v0.0.0-20190308221718-c2843e01d9a2",
			Reference:       "https://ossindex.sonatype.org/component/pkg:golang/golang.org/x/crypto@v0.0.0-20190308221718-c2843e01d9a2",
			Vulnerabilities: []types.Vulnerability{},
		},
		{
			Coordinates:     "pkg:golang/github.com/go-yaml/yaml@v2.2.2",
			Reference:       "https://ossindex.sonatype.org/component/pkg:golang/github.com/go-yaml/yaml@v2.2.2",
			Vulnerabilities: []types.Vulnerability{},
		},
	})

	httpmock.RegisterResponder("POST", "https://ossindex.sonatype.org/api/v3/component-report",
		httpmock.NewStringResponder(200, string(jsonCoordinates)))

	httpmock.RegisterResponder("GET", "http://sillyplace.com:8090/api/v2/applications?publicId=testapp",
		httpmock.NewBytesResponder(404, []byte("")))

	var purls []string
	purls = append(purls, "pkg:golang/github.com/go-yaml/yaml@v2.2.2")
	purls = append(purls, "pkg:golang/golang.org/x/crypto@v0.0.0-20190308221718-c2843e01d9a2")

	iq := setupIQServer()

	_, err := iq.AuditPackages(purls)
	if err == nil {
		t.Error("There is an error")
	}
}

func TestAuditPackagesWithOssiError(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	// clear ossi cache so call to ossi is executed
	logger, _ := test.NewNullLogger()
	ossindexServer := ossindex.New(logger, types.Options{DBCacheName: setupIqOptions().DBCacheName})
	assert.Nil(t, ossindexServer.NoCacheNoProblems())

	httpmock.RegisterResponder("POST", "https://ossindex.sonatype.org/api/v3/component-report",
		httpmock.NewBytesResponder(404, []byte("")))

	httpmock.RegisterResponder("GET", "http://sillyplace.com:8090/api/v2/applications?publicId=testapp",
		httpmock.NewStringResponder(200, applicationsResponse))

	var purls []string
	purls = append(purls, "pkg:golang/github.com/go-yaml/yaml@v2.2.2")
	purls = append(purls, "pkg:golang/golang.org/x/crypto@v0.0.0-20190308221718-c2843e01d9a2")

	iq := setupIQServer()

	_, err := iq.AuditPackages(purls)
	assert.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "There was an issue auditing packages using OSS Index"), err)
}

func TestAuditPackagesThirdPartyAPIResponseNotFound(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	jsonCoordinates, _ := json.Marshal([]types.Coordinate{
		{
			Coordinates:     "pkg:golang/golang.org/x/crypto@v0.0.0-20190308221718-c2843e01d9a2",
			Reference:       "https://ossindex.sonatype.org/component/pkg:golang/golang.org/x/crypto@v0.0.0-20190308221718-c2843e01d9a2",
			Vulnerabilities: []types.Vulnerability{},
		},
		{
			Coordinates:     "pkg:golang/github.com/go-yaml/yaml@v2.2.2",
			Reference:       "https://ossindex.sonatype.org/component/pkg:golang/github.com/go-yaml/yaml@v2.2.2",
			Vulnerabilities: []types.Vulnerability{},
		},
	})

	httpmock.RegisterResponder("POST", "https://ossindex.sonatype.org/api/v3/component-report",
		httpmock.NewStringResponder(200, string(jsonCoordinates)))

	httpmock.RegisterResponder("GET", "http://sillyplace.com:8090/api/v2/applications?publicId=testapp",
		httpmock.NewStringResponder(200, applicationsResponse))

	httpmock.RegisterResponder("POST", "http://sillyplace.com:8090/api/v2/scan/applications/4bb67dcfc86344e3a483832f8c496419/sources/nancy?stageId=develop",
		httpmock.NewBytesResponder(404, []byte("")))

	var purls []string
	purls = append(purls, "pkg:golang/github.com/go-yaml/yaml@v2.2.2")
	purls = append(purls, "pkg:golang/golang.org/x/crypto@v0.0.0-20190308221718-c2843e01d9a2")

	iq := setupIQServer()

	_, err := iq.AuditPackages(purls)
	assert.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "status_code: 404, body: "), err)
}

func TestAuditPackagesThirdPartyAPIMissingResultURL(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	jsonCoordinates, _ := json.Marshal([]types.Coordinate{
		{
			Coordinates:     "pkg:golang/golang.org/x/crypto@v0.0.0-20190308221718-c2843e01d9a2",
			Reference:       "https://ossindex.sonatype.org/component/pkg:golang/golang.org/x/crypto@v0.0.0-20190308221718-c2843e01d9a2",
			Vulnerabilities: []types.Vulnerability{},
		},
		{
			Coordinates:     "pkg:golang/github.com/go-yaml/yaml@v2.2.2",
			Reference:       "https://ossindex.sonatype.org/component/pkg:golang/github.com/go-yaml/yaml@v2.2.2",
			Vulnerabilities: []types.Vulnerability{},
		},
	})

	httpmock.RegisterResponder("POST", "https://ossindex.sonatype.org/api/v3/component-report",
		httpmock.NewStringResponder(200, string(jsonCoordinates)))

	httpmock.RegisterResponder("GET", "http://sillyplace.com:8090/api/v2/applications?publicId=testapp",
		httpmock.NewStringResponder(200, applicationsResponse))

	httpmock.RegisterResponder("POST", "http://sillyplace.com:8090/api/v2/scan/applications/4bb67dcfc86344e3a483832f8c496419/sources/nancy?stageId=develop",
		httpmock.NewBytesResponder(202, []byte("{\"statusUrl\": \"\"}")))

	var purls []string
	purls = append(purls, "pkg:golang/github.com/go-yaml/yaml@v2.2.2")
	purls = append(purls, "pkg:golang/golang.org/x/crypto@v0.0.0-20190308221718-c2843e01d9a2")

	iq := setupIQServer()

	_, err := iq.AuditPackages(purls)
	assert.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "There was an issue obtaining a StatusURL"), err)
}

func TestAuditPackagesIqUpButBadThirdPartyAPIResponse(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	jsonCoordinates, _ := json.Marshal([]types.Coordinate{
		{
			Coordinates:     "pkg:golang/golang.org/x/crypto@v0.0.0-20190308221718-c2843e01d9a2",
			Reference:       "https://ossindex.sonatype.org/component/pkg:golang/golang.org/x/crypto@v0.0.0-20190308221718-c2843e01d9a2",
			Vulnerabilities: []types.Vulnerability{},
		},
		{
			Coordinates:     "pkg:golang/github.com/go-yaml/yaml@v2.2.2",
			Reference:       "https://ossindex.sonatype.org/component/pkg:golang/github.com/go-yaml/yaml@v2.2.2",
			Vulnerabilities: []types.Vulnerability{},
		},
	})

	httpmock.RegisterResponder("POST", "https://ossindex.sonatype.org/api/v3/component-report",
		httpmock.NewStringResponder(200, string(jsonCoordinates)))

	httpmock.RegisterResponder("GET", "http://sillyplace.com:8090/api/v2/applications?publicId=testapp",
		httpmock.NewStringResponder(200, applicationsResponse))

	httpmock.RegisterResponder("POST", "http://sillyplace.com:8090/api/v2/scan/applications/4bb67dcfc86344e3a483832f8c496419/sources/nancy?stageId=develop",
		httpmock.NewBytesResponder(500, []byte("")))

	var purls []string
	purls = append(purls, "pkg:golang/github.com/go-yaml/yaml@v2.2.2")
	purls = append(purls, "pkg:golang/golang.org/x/crypto@v0.0.0-20190308221718-c2843e01d9a2")

	iq := setupIQServer()

	_, err := iq.AuditPackages(purls)
	if err == nil {
		t.Error("There is an error")
	}
}

func setupIQServer() *Server {
	logger, _ := test.NewNullLogger()
	return New(logger, setupIqOptions())
}

// use compiler to ensure IServer interface is implemented by Server
var _ IServer = (*Server)(nil)
