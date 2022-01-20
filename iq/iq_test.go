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
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/package-url/packageurl-go"
	"github.com/sonatype-nexus-community/go-sona-types/cyclonedx"
	"github.com/sonatype-nexus-community/go-sona-types/ossindex"

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

const organizationsResponse = `{
    "organizations": [
        {
            "id": "ROOT_ORGANIZATION_ID",
            "name": "Root Organization",
            "tags": [
                {
                    "id": "5183820023bf4e27bb326203525b858b",
                    "name": "Distributed",
                    "description": "Applications that are provided for consumption outside the company",
                    "color": "yellow"
                },
                {
                    "id": "05f86514787a4b1389998eb84c219cc9",
                    "name": "Hosted",
                    "description": "Applications that are hosted such as services or software as a service.",
                    "color": "light-purple"
                },
                {
                    "id": "695770365dad40d5a381d1865df58393",
                    "name": "Internal",
                    "description": "Applications that are used only by your employees",
                    "color": "dark-green"
                }
            ]
        },
        {
            "id": "9eb917606b8b4debb46328336009eefa",
            "name": "Sandbox Organization",
            "tags": []
        },
        {
            "id": "someFakedOrganizationIDForDefaultAppCreation",
            "name": "My Parent Organization Name",
            "tags": [
				{
                    "id": "695770365dad40d5a381d1865df58399",
                    "name": "MyTagName",
                    "description": "My Tag Description",
                    "color": "dark-green"
                }
			]
        }
    ]
}`

const createApplicationResponse = `{
    "id": "123a08ddc9cd40aab4bc347e9e66f799",
    "publicId": "testapp",
    "name": "testapp",
    "organizationId": "9eb917606b8b4debb46328336009eefa",
    "contactUserName": "admin",
    "applicationTags": []
}`

const thirdPartyAPIResultJSON = `{
		"statusUrl": "api/v2/scan/applications/4bb67dcfc86344e3a483832f8c496419/status/9cee2b6366fc4d328edc318eae46b2cb"
}`

const pollingResult = `{
	"policyAction": "None",
	"reportHtmlUrl": "http://sillyplace.com:8090/ui/links/application/test-app/report/95c4c14e",
	"isError": false
}`

// since IQ 104
const pollingResultRelative = `{
	"policyAction": "None",
	"reportHtmlUrl": "ui/links/application/test-app/report/95c4c14e",
	"reportPdfUrl": "ui/links/application/test-app/report/95c4c14e/pdf",
	"reportDataUrl": "api/v2/applications/test-app/reports/95c4c14e/raw",
	"embeddableReportHtmlUrl": "ui/links/application/test-app/report/95c4c14e/embeddable",
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

func TestNewRequiredAndModifiedOptions(t *testing.T) {
	server, err := New(nil, Options{})
	assert.Equal(t, fmt.Errorf("missing logger"), err)
	assert.Nil(t, server)

	logger, _ := test.NewNullLogger()
	server, err = New(logger, Options{})
	assert.Equal(t, fmt.Errorf("missing options.Application"), err)
	assert.Nil(t, server)

	server, err = New(logger, Options{Application: "myAppId"})
	assert.Equal(t, fmt.Errorf("missing options.Server"), err)
	assert.Nil(t, server)

	server, err = New(logger, Options{Application: "myAppId", Server: "myServer"})
	assert.Equal(t, fmt.Errorf("missing options.User"), err)
	assert.Nil(t, server)

	server, err = New(logger, Options{Application: "myAppId", Server: "myServer", User: "myUser"})
	assert.Equal(t, fmt.Errorf("missing options.Token"), err)
	assert.Nil(t, server)

	server, err = New(logger, Options{Application: "myAppId", Server: "myServer", User: "myUser", Token: "myToken"})
	assert.NotNil(t, server)
	assert.Nil(t, err)

	server, err = New(logger, Options{Application: "myAppId", Server: "myServer/", User: "myUser", Token: "myToken"})
	assert.NotNil(t, server)
	assert.Nil(t, err)
	assert.Equal(t, server.Options.Server, "myServer")
}

func Test_audit_WithStatusUnmarshalError(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	httpmock.RegisterResponder("POST", "http://sillyplace.com:8090/api/v2/scan/applications/4bb67dcfc86344e3a483832f8c496419/sources/nancy?stageId=develop",
		httpmock.NewStringResponder(202, thirdPartyAPIResultJSON))

	httpmock.RegisterResponder("GET", "http://sillyplace.com:8090/api/v2/scan/applications/4bb67dcfc86344e3a483832f8c496419/status/9cee2b6366fc4d328edc318eae46b2cb",
		httpmock.NewStringResponder(200, pollingResult+"bogusResponseData"))

	iq := setupIQServer(t)
	result, err := iq.audit("", "4bb67dcfc86344e3a483832f8c496419")
	assert.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "Could not unmarshal response from IQ server"))
	assert.Equal(t, StatusURLResult{}, result)
}

func Test_audit_WithPollCountMaxExceeded(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	httpmock.RegisterResponder("POST", "http://sillyplace.com:8090/api/v2/scan/applications/4bb67dcfc86344e3a483832f8c496419/sources/nancy?stageId=develop",
		httpmock.NewStringResponder(202, thirdPartyAPIResultJSON))

	httpmock.RegisterResponder("GET", "http://sillyplace.com:8090/api/v2/scan/applications/4bb67dcfc86344e3a483832f8c496419/status/9cee2b6366fc4d328edc318eae46b2cb",
		httpmock.NewStringResponder(404, "").Times(3))

	iq := setupIQServer(t)
	iq.Options.MaxRetries = 2
	result, err := iq.audit("", "4bb67dcfc86344e3a483832f8c496419")
	assert.Error(t, err)
	assert.Equal(t, "exceeded max retries: 2", err.Error())
	assert.Equal(t, StatusURLResult{}, result)
	assert.Equal(t, 3, iq.tries)
}

func Test_populateAbsoluteURL(t *testing.T) {
	iq := setupIQServer(t)

	// defaults, just for completeness
	statusURLResp.populateAbsoluteURL(iq.Options.Server)
	assert.Equal(t, "http://sillyplace.com:8090/", statusURLResp.AbsoluteReportHTMLURL)

	// slash prefix on relative url
	statusURLResp.ReportHTMLURL = "/myReport"
	statusURLResp.populateAbsoluteURL(iq.Options.Server)
	assert.Equal(t, "http://sillyplace.com:8090/myReport", statusURLResp.AbsoluteReportHTMLURL)

	// slash suffix on server url
	iq.Options.Server = "http://sillyplace.com:8090/"
	statusURLResp.ReportHTMLURL = "myReport"
	statusURLResp.populateAbsoluteURL(iq.Options.Server)
	assert.Equal(t, "http://sillyplace.com:8090/myReport", statusURLResp.AbsoluteReportHTMLURL)

	// slashes everywhere - we don't avoid double slash-ery
	iq.Options.Server = "http://sillyplace.com:8090/"
	statusURLResp.ReportHTMLURL = "/myReport"
	statusURLResp.populateAbsoluteURL(iq.Options.Server)
	assert.Equal(t, "http://sillyplace.com:8090/myReport", statusURLResp.AbsoluteReportHTMLURL)

	// no slashes anywhere
	iq.Options.Server = "http://sillyplace.com:8090"
	statusURLResp.ReportHTMLURL = "myReport"
	statusURLResp.populateAbsoluteURL(iq.Options.Server)
	assert.Equal(t, "http://sillyplace.com:8090/myReport", statusURLResp.AbsoluteReportHTMLURL)

	// absolute report url (the way it looks prior to iq 104+)
	iq.Options.Server = "http://sillyplace.com:8090"
	statusURLResp.ReportHTMLURL = "http://sillyplace.com:8090/myReport"
	statusURLResp.populateAbsoluteURL(iq.Options.Server)
	assert.Equal(t, "http://sillyplace.com:8090/myReport", statusURLResp.AbsoluteReportHTMLURL)

	// oh the emptiness
	iq.Options.Server = ""
	statusURLResp.ReportHTMLURL = ""
	statusURLResp.populateAbsoluteURL(iq.Options.Server)
	assert.Equal(t, "/", statusURLResp.AbsoluteReportHTMLURL)

	// parent directory weirdness
	iq.Options.Server = "http://sillyplace.com:8090/./../"
	statusURLResp.ReportHTMLURL = "/../myReport"
	statusURLResp.populateAbsoluteURL(iq.Options.Server)
	assert.Equal(t, "http://sillyplace.com:8090/./../../myReport", statusURLResp.AbsoluteReportHTMLURL)
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

	iq := setupIQServer(t)

	result, _ := iq.AuditPackages(purls)

	statusExpected := StatusURLResult{PolicyAction: PolicyActionNone,
		ReportHTMLURL:         "http://sillyplace.com:8090/ui/links/application/test-app/report/95c4c14e",
		AbsoluteReportHTMLURL: "http://sillyplace.com:8090/ui/links/application/test-app/report/95c4c14e",
	}

	assert.Equal(t, statusExpected, result)
}

func TestAuditPackagesRelativeResult(t *testing.T) {
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
		httpmock.NewStringResponder(200, pollingResultRelative))

	var purls []string
	purls = append(purls, "pkg:golang/github.com/go-yaml/yaml@v2.2.2")
	purls = append(purls, "pkg:golang/golang.org/x/crypto@v0.0.0-20190308221718-c2843e01d9a2")

	iq := setupIQServer(t)

	result, _ := iq.AuditPackages(purls)

	statusExpected := StatusURLResult{PolicyAction: PolicyActionNone,
		ReportHTMLURL:         "ui/links/application/test-app/report/95c4c14e",
		AbsoluteReportHTMLURL: "http://sillyplace.com:8090/ui/links/application/test-app/report/95c4c14e",
	}

	assert.Equal(t, statusExpected, result)
}

func TestAuditPackagesWithSBOM(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	httpmock.RegisterResponder("GET", "http://sillyplace.com:8090/api/v2/applications?publicId=testapp",
		httpmock.NewStringResponder(200, applicationsResponse))

	httpmock.RegisterResponder("POST", "http://sillyplace.com:8090/api/v2/scan/applications/4bb67dcfc86344e3a483832f8c496419/sources/nancy?stageId=develop",
		httpmock.NewStringResponder(202, thirdPartyAPIResultJSON))

	httpmock.RegisterResponder("GET", "http://sillyplace.com:8090/api/v2/scan/applications/4bb67dcfc86344e3a483832f8c496419/status/9cee2b6366fc4d328edc318eae46b2cb",
		httpmock.NewStringResponder(200, pollingResult))

	var purls []packageurl.PackageURL
	var purl packageurl.PackageURL
	purl, _ = packageurl.FromString("pkg:golang/github.com/go-yaml/yaml@v2.2.2")
	purls = append(purls, purl)
	purl, _ = packageurl.FromString("pkg:golang/golang.org/x/crypto@v0.0.0-20190308221718-c2843e01d9a2")
	purls = append(purls, purl)

	logger, _ := test.NewNullLogger()
	dx := cyclonedx.Default(logger)

	sbom := dx.FromPackageURLs(purls)

	iq := setupIQServer(t)

	result, _ := iq.AuditWithSbom(sbom)

	statusExpected := StatusURLResult{PolicyAction: PolicyActionNone,
		ReportHTMLURL:         "http://sillyplace.com:8090/ui/links/application/test-app/report/95c4c14e",
		AbsoluteReportHTMLURL: "http://sillyplace.com:8090/ui/links/application/test-app/report/95c4c14e",
	}

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

	iq := setupIQServer(t)

	_, err := iq.AuditPackages(purls)
	if err == nil {
		t.Errorf("err should not be nil, expected an err with the following text: %s", expectedError)
	}
	if err.Error() != expectedError {
		t.Errorf("Error returned is not as expected. Expected: %s but got: %s", expectedError, err.Error())
	}
}

func TestAuditPackagesIqAutoCreateApplicationID(t *testing.T) {
	expectedError := "An error occurred: There was an issue auditing packages using OSS Index, err: Post \"https://ossindex.sonatype.org/api/v3/component-report\": no responder found"
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	httpmock.RegisterResponder("GET", "http://sillyplace.com:8090/api/v2/applications?publicId=testapp",
		httpmock.NewBytesResponder(200, []byte(`{ "applications": [] }`)))

	httpmock.RegisterResponder("GET", "http://sillyplace.com:8090/api/v2/organizations",
		httpmock.NewStringResponder(200, organizationsResponse))

	httpmock.RegisterResponder("POST", "http://sillyplace.com:8090/api/v2/applications",
		httpmock.NewStringResponder(200, createApplicationResponse))

	var purls []string
	purls = append(purls, "pkg:golang/github.com/go-yaml/yaml@v2.2.2")
	purls = append(purls, "pkg:golang/golang.org/x/crypto@v0.0.0-20190308221718-c2843e01d9a2")

	iq := setupIQServer(t)

	// force new app org name (non-root)
	iq.Options.AutomaticApplicationCreationParentOrganizationName = "My Parent Organization Name"

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

	iq := setupIQServer(t)

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

	const errMsgFromIQ = "some error from IQ Server with helpful text"
	httpmock.RegisterResponder("GET", "http://sillyplace.com:8090/api/v2/applications?publicId=testapp",
		httpmock.NewBytesResponder(404, []byte(errMsgFromIQ)))

	var purls []string
	purls = append(purls, "pkg:golang/github.com/go-yaml/yaml@v2.2.2")
	purls = append(purls, "pkg:golang/golang.org/x/crypto@v0.0.0-20190308221718-c2843e01d9a2")

	iq := setupIQServer(t)

	_, err := iq.AuditPackages(purls)
	if err == nil {
		t.Error("There is an error")
	}
	assert.Contains(t, err.Error(), errMsgFromIQ)
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

	iq := setupIQServer(t)

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

	iq := setupIQServer(t)

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

	iq := setupIQServer(t)

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

	iq := setupIQServer(t)

	_, err := iq.AuditPackages(purls)
	if err == nil {
		t.Error("There is an error")
	}
}

func TestPolicyActionEnum(t *testing.T) {
	assert.Equal(t, "None", PolicyActionNone)
	assert.Equal(t, "Warning", PolicyActionWarning)
	assert.Equal(t, "Failure", PolicyActionFailure)
}

func setupIQServer(t *testing.T) (server *Server) {
	logger, _ := test.NewNullLogger()
	server, err := New(logger, setupIqOptions())
	assert.Nil(t, err)
	return
}

// use compiler to ensure IServer interface is implemented by Server
var _ IServer = (*Server)(nil)
