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
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"reflect"
	"time"

	"github.com/briandowns/spinner"
	"github.com/package-url/packageurl-go"
	"github.com/sirupsen/logrus"
	"github.com/sonatype-nexus-community/go-sona-types/cyclonedx"
	"github.com/sonatype-nexus-community/go-sona-types/ossindex"
	"github.com/sonatype-nexus-community/go-sona-types/ossindex/types"
	"github.com/sonatype-nexus-community/go-sona-types/useragent"
)

const internalApplicationIDURL = "/api/v2/applications?publicId="

const createApplicationIDURL = "/api/v2/applications"

const getOrganizationsURL = "/api/v2/organizations"

const thirdPartyAPILeft = "/api/v2/scan/applications/"

const thirdPartyAPIRight = "/sources/nancy?stageId="

// StatusURLResult is a struct to let the consumer know what the response from Nexus IQ Server was
type StatusURLResult struct {
	PolicyAction  string `json:"policyAction"`
	ReportHTMLURL string `json:"reportHtmlUrl"`
	IsError       bool   `json:"isError"`
	ErrorMessage  string `json:"errorMessage"`
}

type organizationResult struct {
	Organizations []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
		Tags []tags `json:"tags"`
	} `json:"organizations"`
}

type applicationCreation struct {
	PublicID        string           `json:"publicId"`
	Name            string           `json:"name"`
	OrganizationID  string           `json:"organizationId"`
	ContactUserName string           `json:"contactUserName"`
	ApplicationTags []applicationTag `json:"applicationTags"`
}

type applicationCreationResponse struct {
	ID              string `json:"id"`
	PublicID        string `json:"publicId"`
	Name            string `json:"name"`
	OrganizationID  string `json:"organizationId"`
	ContactUserName string `json:"contactUserName"`
	ApplicationTags []struct {
		ID            string `json:"id"`
		TagID         string `json:"tagId"`
		ApplicationID string `json:"applicationId"`
	} `json:"applicationTags"`
}

type applicationTag struct {
	TagID string `json:"tagId"`
}

type tags struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Color       string `json:"color"`
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

// ServerError is a custom error type that can be used to differentiate between
// regular errors and errors specific to handling IQ Server
type ServerError struct {
	Err     error
	Message string
}

func (i *ServerError) Error() string {
	if i.Err != nil {
		return fmt.Sprintf("An error occurred: %s, err: %s", i.Message, i.Err.Error())
	}
	return fmt.Sprintf("An error occurred: %s", i.Message)
}

// ApplicationMissingError is a custom error type that can be used to tell that a
// response to IQ was fine, but that no Application exists with that ID
type ApplicationIDError struct {
	ApplicationID string
}

func (i *ApplicationIDError) Error() string {
	return fmt.Sprint("Unable to retrieve an internal ID for the specified public application ID:", i.ApplicationID)
}

type ServerErrorMissingLicense struct {
}

func (i *ServerErrorMissingLicense) Error() string {
	return "error accessing nexus iq server: No valid product license installed"
}

// IServer is an interface that can be used for mocking the Server struct
type IServer interface {
	AuditPackages(p []string) (StatusURLResult, error)
}

// Server is a struct that holds the IQ Server options, logger and other properties related to
// communicating with Nexus IQ Server
type Server struct {
	// Options is the accepted Options for communicating with IQ Server, and OSS Index (see Options struct)
	// for more information
	Options Options
	// logLady is the internal name of the logger, and accepts a pointer to a *logrus.Logger
	logLady *logrus.Logger
	// agent is a pointer to a *useragent.Agent struct, used for setting the User-Agent when communicating
	// with IQ Server and OSS Index
	agent *useragent.Agent
	// tries is an internal variable for keeping track of how many times IQ Server has been polled
	tries int
}

// Options is a struct for setting options on the Server struct
type Options struct {
	// User is the IQ Server user you intend to authenticate with
	User string
	// Token is the IQ Server token you intend to authenticate with
	Token string
	// Stage is the IQ Server stage you intend to generate a report with (ex: develop, build, release, etc...)
	Stage string
	// Application is the IQ Server public application ID you intend to run the audit with
	Application string
	// Server is the IQ Server base URL (ex: http://localhost:8070)
	Server string
	// MaxRetries is the maximum amount of times to long poll IQ Server for results
	MaxRetries int
	// Tool is the client-id you want to have set in your User-Agent string (ex: nancy-client)
	Tool string
	// Version is the version of the tool you are writing, that you want set in your User-Agent string (ex: 1.0.0)
	Version string
	// User is the OSS Index user you intend to authenticate with
	OSSIndexUser string
	// Token is the OSS Index token you intend to authenticate with
	OSSIndexToken string
	// DBCacheName is the name of the OSS Index cache you'd like to use (ex: nancy-cache)
	DBCacheName string
	// TTL is the maximum time you want items to live in the DB Cache before being evicted (defaults to 12 hours)
	TTL time.Time
	// PollInterval is the time you want to wait between polls of IQ Server (defaults to 1 second)
	PollInterval time.Duration
}

// New is intended to be the way to obtain a iq instance, where you control the options
func New(logger *logrus.Logger, options Options) (server *Server, err error) {
	if logger == nil {
		err = fmt.Errorf("missing logger")
		return
	}

	if err = validateRequiredOption(options, "Application"); err != nil {
		return
	}
	if err = validateRequiredOption(options, "Server"); err != nil {
		return
	}
	if err = validateRequiredOption(options, "User"); err != nil {
		return
	}
	if err = validateRequiredOption(options, "Token"); err != nil {
		return
	}

	if options.PollInterval == 0 {
		logger.Trace("Setting Poll Interval to 1 second since it wasn't set explicitly")
		options.PollInterval = 1 * time.Second
	}

	if options.TTL.IsZero() {
		logger.Trace("Setting TTL to 12 hours since it wasn't set explicitly")
		options.TTL = time.Now().Local().Add(time.Hour * 12)
	}

	ua := useragent.New(logger, useragent.Options{ClientTool: options.Tool, Version: options.Version})

	server = &Server{logLady: logger, Options: options, tries: 0, agent: ua}
	return
}

func validateRequiredOption(options Options, optionName string) (err error) {
	e := reflect.ValueOf(&options).Elem()
	zero := e.FieldByName(optionName).IsZero()
	if zero {
		err = fmt.Errorf("missing options.%s", optionName)
	}
	return
}

// Audit accepts a slice of packageurl.PackageURL, and slice of []cyclonedx.File and will submit these to
// Nexus IQ Server for audit, and return a struct of StatusURLResult
func (i *Server) Audit(purls []packageurl.PackageURL, sha1s []cyclonedx.File) (StatusURLResult, error) {
	i.logLady.WithFields(logrus.Fields{
		"purls":          purls,
		"application_id": i.Options.Application,
	}).Info("Beginning audit with IQ using packageurl.PackageURL")

	if i.Options.User == "admin" && i.Options.Token == "admin123" {
		i.logLady.Info("Warning user of questionable life choices related to username and password")
		warnUserOfBadLifeChoices()
	}

	internalID, err := i.getOrCreateInternalApplicationID(i.Options.Application)
	if internalID == "" && err != nil {
		i.logLady.Error("Internal ID not obtained from Nexus IQ")
		return statusURLResp, err
	}

	dx := cyclonedx.Default(i.logLady)

	sbom := dx.FromPackageURLsAndSha1s(purls, sha1s)
	i.logLady.WithField("sbom", sbom).Debug("Obtained cyclonedx SBOM")

	return i.getStatusURL(internalID, sbom)
}

// AuditPackages accepts a slice of purls, and configuration, and will submit these to
// Nexus IQ Server for audit, and return a struct of StatusURLResult
func (i *Server) AuditPackages(purls []string) (StatusURLResult, error) {
	i.logLady.WithFields(logrus.Fields{
		"purls":          purls,
		"application_id": i.Options.Application,
	}).Info("Beginning audit with IQ")

	if i.Options.User == "admin" && i.Options.Token == "admin123" {
		i.logLady.Info("Warning user of questionable life choices related to username and password")
		warnUserOfBadLifeChoices()
	}

	internalID, err := i.getInternalApplicationID(i.Options.Application)
	if internalID == "" && err != nil {
		i.logLady.Error("Internal ID not obtained from Nexus IQ")
		return statusURLResp, err
	}

	ossIndexOptions := types.Options{
		Username:    i.Options.OSSIndexUser,
		Token:       i.Options.OSSIndexToken,
		DBCacheName: i.Options.DBCacheName,
		TTL:         i.Options.TTL,
	}

	ossi := ossindex.New(i.logLady, ossIndexOptions)

	resultsFromOssIndex, err := ossi.AuditPackages(purls)
	if err != nil {
		return statusURLResp, &ServerError{
			Err:     err,
			Message: "There was an issue auditing packages using OSS Index",
		}
	}

	dx := cyclonedx.Default(i.logLady)

	sbom := dx.FromCoordinates(resultsFromOssIndex)
	i.logLady.WithField("sbom", sbom).Debug("Obtained cyclonedx SBOM")

	return i.getStatusURL(internalID, sbom)
}

func (i *Server) getStatusURL(internalID string, sbom string) (StatusURLResult, error) {
	i.logLady.WithFields(logrus.Fields{
		"internal_id": internalID,
		"sbom":        sbom,
	}).Debug("Submitting to Third Party API")
	statusURL, err := i.submitToThirdPartyAPI(sbom, internalID)
	if err != nil {
		return statusURLResp, &ServerError{
			Err:     err,
			Message: "There was an issue submitting to the Third Party API",
		}
	}
	if statusURL == "" {
		i.logLady.Error("StatusURL not obtained from Third Party API")
		return statusURLResp, &ServerError{
			Err:     fmt.Errorf("There was an issue submitting your sbom to the Nexus IQ Third Party API, sbom: %s", sbom),
			Message: "There was an issue obtaining a StatusURL",
		}
	}

	statusURLResp = StatusURLResult{}

	finishedChan := make(chan resultError)
	defer close(finishedChan)

	s := spinner.New(spinner.CharSets[11], 400*time.Millisecond)
	s.Suffix = " Polling Nexus IQ Server"
	s.FinalMSG = "Finished Polling Nexus IQ Server"
	s.Start()
	go func() resultError {
		for {
			select {
			case <-finishedChan:
				return resultError{finished: true}
			default:
				if err = i.pollIQServer(fmt.Sprintf("%s/%s", i.Options.Server, statusURL), finishedChan); err != nil {
					return resultError{finished: false, err: err}
				}
				time.Sleep(i.Options.PollInterval)
			}
		}
	}()

	r := <-finishedChan
	s.Stop()
	return statusURLResp, r.err
}

func (i *Server) getOrCreateInternalApplicationID(applicationID string) (appID string, err error) {
	appID, err = i.getInternalApplicationID(applicationID)
	if err != nil {
		if _, ok := err.(*ApplicationIDError); ok {
			i.logLady.Debug("No Application ID found, attempting to create one")
			return i.createApplicationID(applicationID)
		}
		return
	}

	return
}

func (i *Server) getOrganizations() (organizationResult, error) {
	client := &http.Client{}

	req, err := http.NewRequest(
		"GET",
		fmt.Sprintf("%s%s", i.Options.Server, getOrganizationsURL),
		nil,
	)
	if err != nil {
		return organizationResult{}, &ServerError{
			Err:     err,
			Message: "Setup of request for getting organizations failed",
		}
	}
	req.SetBasicAuth(i.Options.User, i.Options.Token)
	req.Header.Set("User-Agent", i.agent.GetUserAgent())

	resp, err := client.Do(req)
	if err != nil {
		return organizationResult{}, &ServerError{
			Err:     err,
			Message: "There was an error communicating with Nexus IQ Server to get a list of organizations",
		}
	}

	if resp.StatusCode == http.StatusPaymentRequired {
		i.logLady.WithField("resp_status_code", resp.Status).Error("Error accessing Nexus IQ Server due to product license")
		return organizationResult{}, &ServerErrorMissingLicense{}
	}

	//noinspection GoUnhandledErrorResult
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		bodyBytes, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return organizationResult{}, &ServerError{
				Err:     err,
				Message: "There was an error retrieving the bytes of the response for getting your internal application ID from Nexus IQ Server",
			}
		}

		var orgs organizationResult
		err = json.Unmarshal(bodyBytes, &orgs)
		if err != nil {
			return organizationResult{}, &ServerError{
				Err:     err,
				Message: "failed to unmarshal response",
			}
		}
	}
	return organizationResult{}, &ServerError{
		Err:     fmt.Errorf("Unable to communicate with Nexus IQ Server, status code returned is: %d", resp.StatusCode),
		Message: "Unable to communicate with Nexus IQ Server",
	}
}

func (i *Server) createApplicationID(applicationID string) (appID string, err error) {
	client := &http.Client{}
	orgs, err := i.getOrganizations()
	if err != nil {
		return "", err
	}

	orgID := ""
	var tagIDs []applicationTag

	if len(orgs.Organizations) > 0 {
		orgID = orgs.Organizations[0].ID

		if len(orgs.Organizations[0].Tags) > 0 {
			for _, v := range orgs.Organizations[0].Tags {
				tagIDs = append(tagIDs, applicationTag{TagID: v.ID})
			}
		}
	} else {
		return "", errors.New("No organization IDs found")
	}

	app := applicationCreation{
		PublicID:        applicationID,
		Name:            applicationID,
		OrganizationID:  orgID,
		ContactUserName: i.Options.User,
		ApplicationTags: tagIDs,
	}

	js, err := json.Marshal(app)
	if err != nil {
		return "", errors.New("Unable to marshall json")
	}

	req, err := http.NewRequest(
		"POST",
		fmt.Sprintf("%s%s", i.Options.Server, createApplicationIDURL),
		bytes.NewBuffer(js),
	)
	if err != nil {
		return "", &ServerError{
			Err:     err,
			Message: "Setup of request to create internal application id failed",
		}
	}

	req.SetBasicAuth(i.Options.User, i.Options.Token)
	req.Header.Set("User-Agent", i.agent.GetUserAgent())

	resp, err := client.Do(req)
	if err != nil {
		return "", &ServerError{
			Err:     err,
			Message: "There was an error communicating with Nexus IQ Server to create your application ID",
		}
	}

	if resp.StatusCode == http.StatusPaymentRequired {
		i.logLady.WithField("resp_status_code", resp.Status).Error("Error accessing Nexus IQ Server due to product license")
		return "", &ServerErrorMissingLicense{}
	}

	//noinspection GoUnhandledErrorResult
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		bodyBytes, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return "", &ServerError{
				Err:     err,
				Message: "There was an error retrieving the bytes of the response for getting your internal application ID from Nexus IQ Server",
			}
		}

		var response applicationCreationResponse
		err = json.Unmarshal(bodyBytes, &response)
		if err != nil {
			return "", &ServerError{
				Err:     err,
				Message: "failed to unmarshal response",
			}
		}

		if response.ID != "" {
			i.logLady.WithFields(logrus.Fields{
				"internal_id": response.ID,
			}).Debug("Created internal ID with Nexus IQ Server")

			return response.ID, nil
		}

		i.logLady.WithFields(logrus.Fields{
			"application_id": applicationID,
		}).Error("Unable to retrieve an internal ID for the specified public application ID")

		return "", &ServerError{
			Err:     fmt.Errorf("Unable to retrieve an internal ID for the specified public application ID: %s", applicationID),
			Message: "Unable to retrieve an internal ID",
		}
	}
	i.logLady.WithFields(logrus.Fields{
		"status_code": resp.StatusCode,
	}).Error("Error communicating with Nexus IQ Server application endpoint")
	return "", &ServerError{
		Err:     fmt.Errorf("Unable to communicate with Nexus IQ Server, status code returned is: %d", resp.StatusCode),
		Message: "Unable to communicate with Nexus IQ Server",
	}
}

func (i *Server) getInternalApplicationID(applicationID string) (string, error) {
	client := &http.Client{}

	req, err := http.NewRequest(
		"GET",
		fmt.Sprintf("%s%s%s", i.Options.Server, internalApplicationIDURL, applicationID),
		nil,
	)
	if err != nil {
		return "", &ServerError{
			Err:     err,
			Message: "Request to get internal application id failed",
		}
	}

	req.SetBasicAuth(i.Options.User, i.Options.Token)
	req.Header.Set("User-Agent", i.agent.GetUserAgent())

	resp, err := client.Do(req)
	if err != nil {
		return "", &ServerError{
			Err:     err,
			Message: "There was an error communicating with Nexus IQ Server to get your internal application ID",
		}
	}

	if resp.StatusCode == http.StatusPaymentRequired {
		i.logLady.WithField("resp_status_code", resp.Status).Error("Error accessing Nexus IQ Server due to product license")
		return "", &ServerErrorMissingLicense{}
	}

	//noinspection GoUnhandledErrorResult
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		bodyBytes, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return "", &ServerError{
				Err:     err,
				Message: "There was an error retrieving the bytes of the response for getting your internal application ID from Nexus IQ Server",
			}
		}

		var response applicationResponse
		err = json.Unmarshal(bodyBytes, &response)
		if err != nil {
			return "", &ServerError{
				Err:     err,
				Message: "failed to unmarshal response",
			}
		}

		if response.Applications != nil && len(response.Applications) > 0 {
			i.logLady.WithFields(logrus.Fields{
				"internal_id": response.Applications[0].ID,
			}).Debug("Retrieved internal ID from Nexus IQ Server")

			return response.Applications[0].ID, nil
		}

		i.logLady.WithFields(logrus.Fields{
			"application_id": applicationID,
		}).Error("Unable to retrieve an internal ID for the specified public application ID")

		return "", &ApplicationIDError{}
	}
	i.logLady.WithFields(logrus.Fields{
		"status_code": resp.StatusCode,
	}).Error("Error communicating with Nexus IQ Server application endpoint")
	return "", &ServerError{
		Err:     fmt.Errorf("Unable to communicate with Nexus IQ Server, status code returned is: %d", resp.StatusCode),
		Message: "Unable to communicate with Nexus IQ Server",
	}
}

func (i *Server) submitToThirdPartyAPI(sbom string, internalID string) (string, error) {
	i.logLady.Debug("Beginning to submit to Third Party API")
	client := &http.Client{}

	url := fmt.Sprintf("%s%s", i.Options.Server, fmt.Sprintf("%s%s%s%s", thirdPartyAPILeft, internalID, thirdPartyAPIRight, i.Options.Stage))
	i.logLady.WithField("url", url).Debug("Crafted URL for submission to Third Party API")

	req, err := http.NewRequest(
		"POST",
		url,
		bytes.NewBuffer([]byte(sbom)),
	)
	if err != nil {
		return "", &ServerError{
			Err:     err,
			Message: "Could not POST to Nexus iQ Third Party API",
		}
	}

	req.SetBasicAuth(i.Options.User, i.Options.Token)
	req.Header.Set("User-Agent", i.agent.GetUserAgent())
	req.Header.Set("Content-Type", "application/xml")

	resp, err := client.Do(req)
	if err != nil {
		return "", &ServerError{
			Err:     err,
			Message: "There was an issue communicating with the Nexus IQ Third Party API",
		}
	}

	//noinspection GoUnhandledErrorResult
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusAccepted {
		bodyBytes, err := ioutil.ReadAll(resp.Body)
		i.logLady.WithField("body", string(bodyBytes)).Info("Request accepted")
		if err != nil {
			return "", &ServerError{
				Err:     err,
				Message: "There was an issue submitting your sbom to the Nexus IQ Third Party API",
			}
		}

		var response thirdPartyAPIResult
		err = json.Unmarshal(bodyBytes, &response)
		if err != nil {
			return "", &ServerError{
				Err:     err,
				Message: "Could not unmarshal response from IQ server",
			}
		}
		return response.StatusURL, err
	}

	// something went wrong
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		i.logLady.Error(err)
		// do not return to allow the ServerError below to be returned
	}
	i.logLady.WithFields(logrus.Fields{
		"body":        string(bodyBytes),
		"status_code": resp.StatusCode,
		"status":      resp.Status,
	}).Info("Request not accepted")
	return "", &ServerError{
		Err:     fmt.Errorf("status_code: %d, body: %s, err: %+v", resp.StatusCode, string(bodyBytes), err),
		Message: "There was an issue submitting your sbom to the Nexus IQ Third Party API",
	}
}

func (i *Server) pollIQServer(statusURL string, finished chan resultError) error {
	i.logLady.WithFields(logrus.Fields{
		"attempt_number": i.tries,
		"max_retries":    i.Options.MaxRetries,
		"status_url":     statusURL,
	}).Trace("Polling Nexus IQ for response")
	if i.tries > i.Options.MaxRetries {
		i.logLady.Error("Maximum tries exceeded, finished polling, consider bumping up Max Retries")
		finished <- resultError{finished: true, err: nil}
	}

	client := &http.Client{}
	req, err := http.NewRequest("GET", statusURL, nil)
	if err != nil {
		return &ServerError{
			Err:     err,
			Message: "Could not poll IQ server",
		}
	}

	req.SetBasicAuth(i.Options.User, i.Options.Token)

	req.Header.Set("User-Agent", i.agent.GetUserAgent())

	resp, err := client.Do(req)

	if err != nil {
		finished <- resultError{finished: true, err: err}
		return &ServerError{
			Err:     err,
			Message: "There was an error polling Nexus IQ Server",
		}
	}

	//noinspection GoUnhandledErrorResult
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		bodyBytes, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return &ServerError{
				Err:     err,
				Message: "There was an error with processing the response from polling Nexus IQ Server",
			}
		}

		var response StatusURLResult
		err = json.Unmarshal(bodyBytes, &response)
		if err != nil {
			return &ServerError{
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
	i.tries++
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
