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
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/sonatype-nexus-community/go-sona-types/cyclonedx"
	"github.com/sonatype-nexus-community/go-sona-types/ossindex"
	"github.com/sonatype-nexus-community/go-sona-types/ossindex/types"
	"github.com/sonatype-nexus-community/go-sona-types/useragent"
)

const internalApplicationIDURL = "/api/v2/applications?publicId="

const thirdPartyAPILeft = "/api/v2/scan/applications/"

const thirdPartyAPIRight = "/sources/nancy?stageId="

const (
	pollInterval = 1 * time.Second
)

var (
	localConfig Configuration
	logLady     *logrus.Logger
	tries       = 0
)

// StatusURLResult is a struct to let the consumer know what the response from Nexus IQ Server was
type StatusURLResult struct {
	PolicyAction  string `json:"policyAction"`
	ReportHTMLURL string `json:"reportHtmlUrl"`
	IsError       bool   `json:"isError"`
	ErrorMessage  string `json:"errorMessage"`
}

// Internal types for use by this package, don't need to expose them
type applicationResponse struct {
	Applications []application `json:"applications"`
}

type application struct {
	ID string `json:"id"`
}

type thirdPartyAPIResult struct {
	StatusURL string `json:"statusUrl"`
}

var statusURLResp StatusURLResult

type resultError struct {
	finished bool
	err      error
}

type Configuration struct {
	User          string
	Token         string
	Stage         string
	Application   string
	Server        string
	MaxRetries    int
	Tool          string
	Version       string
	OSSIndexUser  string
	OSSIndexToken string
}

type IQServerError struct {
	Err     error
	Message string
}

func (i *IQServerError) Error() string {
	if i.Err != nil {
		return fmt.Sprintf("An error occurred: %s, err: %s", i.Message, i.Err.Error())
	}
	return fmt.Sprintf("An error occurred: %s", i.Message)
}

// AuditPackages accepts a slice of purls, public application ID, and configuration, and will submit these to
// Nexus IQ Server for audit, and return a struct of StatusURLResult
func AuditPackages(purls []string, applicationID string, config Configuration, logger *logrus.Logger) (StatusURLResult, error) {
	logLady = logger
	logLady.WithFields(logrus.Fields{
		"purls":          purls,
		"application_id": applicationID,
	}).Info("Beginning audit with IQ")
	localConfig = config

	if localConfig.User == "admin" && localConfig.Token == "admin123" {
		logLady.Info("Warning user of questionable life choices related to username and password")
		warnUserOfBadLifeChoices()
	}

	internalID, err := getInternalApplicationID(applicationID)
	if internalID == "" && err != nil {
		logLady.Error("Internal ID not obtained from Nexus IQ")
		return statusURLResp, err
	}

	ossIndexConfig := types.Configuration{Username: localConfig.OSSIndexUser, Token: localConfig.OSSIndexToken}

	resultsFromOssIndex, err := ossindex.AuditPackagesWithOSSIndex(purls, ossIndexConfig, logLady)
	if err != nil {
		return statusURLResp, &IQServerError{
			Err:     err,
			Message: "There was an issue auditing packages using OSS Index",
		}
	}

	sbom := cyclonedx.ProcessPurlsIntoSBOM(resultsFromOssIndex, logLady)
	logLady.WithField("sbom", sbom).Debug("Obtained cyclonedx SBOM")

	logLady.WithFields(logrus.Fields{
		"internal_id": internalID,
		"sbom":        sbom,
	}).Debug("Submitting to Third Party API")
	statusURL, err := submitToThirdPartyAPI(sbom, internalID)
	if err != nil {
		return statusURLResp, &IQServerError{
			Err:     err,
			Message: "There was an issue submitting to the Third Party API",
		}
	}
	if statusURL == "" {
		logLady.Error("StatusURL not obtained from Third Party API")
		return statusURLResp, &IQServerError{
			Err:     fmt.Errorf("There was an issue submitting your sbom to the Nexus IQ Third Party API, sbom: %s", sbom),
			Message: "There was an issue obtaining a StatusURL",
		}
	}

	statusURLResp = StatusURLResult{}

	finishedChan := make(chan resultError)
	defer close(finishedChan)

	go func() resultError {
		for {
			select {
			case <-finishedChan:
				return resultError{finished: true}
			default:
				if err = pollIQServer(fmt.Sprintf("%s/%s", localConfig.Server, statusURL), finishedChan, localConfig.MaxRetries); err != nil {
					return resultError{finished: false, err: err}
				}
				time.Sleep(pollInterval)
			}
		}
	}()

	r := <-finishedChan
	return statusURLResp, r.err
}

func getInternalApplicationID(applicationID string) (string, error) {
	client := &http.Client{}

	req, err := http.NewRequest(
		"GET",
		fmt.Sprintf("%s%s%s", localConfig.Server, internalApplicationIDURL, applicationID),
		nil,
	)
	if err != nil {
		return "", &IQServerError{
			Err:     err,
			Message: "Request to get internal application id failed",
		}
	}

	req.SetBasicAuth(localConfig.User, localConfig.Token)
	req.Header.Set("User-Agent", useragent.GetUserAgent(logLady, localConfig.Version))

	resp, err := client.Do(req)
	if err != nil {
		return "", &IQServerError{
			Err:     err,
			Message: "There was an error communicating with Nexus IQ Server to get your internal application ID",
		}
	}

	//noinspection GoUnhandledErrorResult
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		bodyBytes, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return "", &IQServerError{
				Err:     err,
				Message: "There was an error retrieving the bytes of the response for getting your internal application ID from Nexus IQ Server",
			}
		}

		var response applicationResponse
		err = json.Unmarshal(bodyBytes, &response)
		if err != nil {
			return "", &IQServerError{
				Err:     err,
				Message: "failed to unmarshal response",
			}
		}

		if response.Applications != nil && len(response.Applications) > 0 {
			logLady.WithFields(logrus.Fields{
				"internal_id": response.Applications[0].ID,
			}).Debug("Retrieved internal ID from Nexus IQ Server")

			return response.Applications[0].ID, nil
		}

		logLady.WithFields(logrus.Fields{
			"application_id": applicationID,
		}).Error("Unable to retrieve an internal ID for the specified public application ID")

		return "", &IQServerError{
			Err:     fmt.Errorf("Unable to retrieve an internal ID for the specified public application ID: %s", applicationID),
			Message: "Unable to retrieve an internal ID",
		}
	}
	logLady.WithFields(logrus.Fields{
		"status_code": resp.StatusCode,
	}).Error("Error communicating with Nexus IQ Server application endpoint")
	return "", &IQServerError{
		Err:     fmt.Errorf("Unable to communicate with Nexus IQ Server, status code returned is: %d", resp.StatusCode),
		Message: "Unable to communicate with Nexus IQ Server",
	}
}

func submitToThirdPartyAPI(sbom string, internalID string) (string, error) {
	logLady.Debug("Beginning to submit to Third Party API")
	client := &http.Client{}

	url := fmt.Sprintf("%s%s", localConfig.Server, fmt.Sprintf("%s%s%s%s", thirdPartyAPILeft, internalID, thirdPartyAPIRight, localConfig.Stage))
	logLady.WithField("url", url).Debug("Crafted URL for submission to Third Party API")

	req, err := http.NewRequest(
		"POST",
		url,
		bytes.NewBuffer([]byte(sbom)),
	)
	if err != nil {
		return "", &IQServerError{
			Err:     err,
			Message: "Could not POST to Nexus iQ Third Party API",
		}
	}

	req.SetBasicAuth(localConfig.User, localConfig.Token)
	req.Header.Set("User-Agent", useragent.GetUserAgent(logLady, localConfig.Version))
	req.Header.Set("Content-Type", "application/xml")

	resp, err := client.Do(req)
	if err != nil {
		return "", &IQServerError{
			Err:     err,
			Message: "There was an issue communicating with the Nexus IQ Third Party API",
		}
	}

	//noinspection GoUnhandledErrorResult
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusAccepted {
		bodyBytes, err := ioutil.ReadAll(resp.Body)
		logLady.WithField("body", string(bodyBytes)).Info("Request accepted")
		if err != nil {
			return "", &IQServerError{
				Err:     err,
				Message: "There was an issue submitting your sbom to the Nexus IQ Third Party API",
			}
		}

		var response thirdPartyAPIResult
		err = json.Unmarshal(bodyBytes, &response)
		if err != nil {
			return "", &IQServerError{
				Err:     err,
				Message: "Could not unmarshal response from IQ server",
			}
		}
		return response.StatusURL, err
	}
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	logLady.WithFields(logrus.Fields{
		"body":        string(bodyBytes),
		"status_code": resp.StatusCode,
		"status":      resp.Status,
	}).Info("Request not accepted")
	if err != nil {
		return "", &IQServerError{
			Err:     err,
			Message: "There was an issue submitting your sbom to the Nexus IQ Third Party API",
		}
	}

	return "", err
}

func pollIQServer(statusURL string, finished chan resultError, maxRetries int) error {
	logLady.WithFields(logrus.Fields{
		"attempt_number": tries,
		"max_retries":    maxRetries,
		"status_url":     statusURL,
	}).Trace("Polling Nexus IQ for response")
	if tries > maxRetries {
		logLady.Error("Maximum tries exceeded, finished polling, consider bumping up Max Retries")
		finished <- resultError{finished: true, err: nil}
	}

	client := &http.Client{}
	req, err := http.NewRequest("GET", statusURL, nil)
	if err != nil {
		return &IQServerError{
			Err:     err,
			Message: "Could not poll IQ server",
		}
	}

	req.SetBasicAuth(localConfig.User, localConfig.Token)

	req.Header.Set("User-Agent", useragent.GetUserAgent(logLady, localConfig.Version))

	resp, err := client.Do(req)

	if err != nil {
		finished <- resultError{finished: true, err: err}
		return &IQServerError{
			Err:     err,
			Message: "There was an error polling Nexus IQ Server",
		}
	}

	//noinspection GoUnhandledErrorResult
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		bodyBytes, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return &IQServerError{
				Err:     err,
				Message: "There was an error with processing the response from polling Nexus IQ Server",
			}
		}

		var response StatusURLResult
		err = json.Unmarshal(bodyBytes, &response)
		if err != nil {
			return &IQServerError{
				Err:     err,
				Message: "Could not unmarshal response from IQ server",
			}
		}
		statusURLResp = response
		if response.IsError {
			finished <- resultError{finished: true, err: nil}
		}
		finished <- resultError{finished: true, err: nil}
	}
	tries++
	fmt.Print(".")
	return err
}

func warnUserOfBadLifeChoices() {
	fmt.Println()
	fmt.Println("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
	fmt.Println("!!!! WARNING : You are using the default username and password for Nexus IQ. !!!!")
	fmt.Println("!!!! You are strongly encouraged to change these, and use a token.           !!!!")
	fmt.Println("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
	fmt.Println()
}
