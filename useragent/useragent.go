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

// Package useragent has functions for setting a user agent with helpful information
package useragent

import (
	"fmt"
	"github.com/sonatype-nexus-community/go-sona-types/internal"
	"os"
	"runtime"

	"github.com/sirupsen/logrus"
)

// IAgent is an interface for mocking the Agent struct
type IAgent interface {
	GetUserAgent() string
}

// Agent is a struct that holds the User-Agent options, logger and other properties related to
// obtaining a properly formatted user-agent
type Agent struct {
	Options Options
	logLady *logrus.Logger
}

// Options is a struct that holds the User-Agent options
type Options struct {
	GoOS       string
	GoArch     string
	ClientTool string
	Version    string
}

func New(logger *logrus.Logger, options Options) *Agent {
	return &Agent{Options: options, logLady: logger}
}

func Default(logger *logrus.Logger) *Agent {
	options := Options{
		Version:    "development",
		GoArch:     runtime.GOARCH,
		GoOS:       runtime.GOOS,
		ClientTool: "nancy-client",
	}
	return New(logger, options)
}

// GetUserAgent provides a user-agent to nancy that provides info on what version of nancy
// (or upstream consumers like ahab or cheque) is running, and if the process is being run in
// CI. If so, it looks for what CI system, and other information such as SC_CALLER_INFO which
// can be used to tell if nancy is being ran inside an orb, bitbucket pipeline, etc... that
// we authored
func (a *Agent) GetUserAgent() string {
	a.logLady.Debug("Obtaining User Agent")
	// where callTree format is:
	// toolName__toolVersion___subToolName__subToolVersion___subSubToolName__subSubToolVersion
	//
	// double underscore "__" delimits Name/Version
	// triple underscore "___" delimits currentCaller/priorCaller/priorPriorCaller
	callTree := getCallerInfo()
	if internal.CheckForCIEnvironment() {
		return a.checkCIEnvironments(callTree)
	}
	return a.getUserAgent("non ci usage", callTree)
}

func (a *Agent) getUserAgentBaseAndVersion() (baseAgent string) {
	a.logLady.Trace("Attempting to obtain user agent and version")
	baseAgent = fmt.Sprintf("%s/%s", a.Options.ClientTool, a.Options.Version)
	a.logLady.WithField("user_agent_base", baseAgent).Trace("Obtained user agent and version")
	return
}

func (a *Agent) checkCIEnvironments(callTree string) string {
	if checkForCISystem("CIRCLECI") {
		a.logLady.Trace("CircleCI usage")
		return a.getUserAgent("circleci", callTree)
	}
	if checkForCISystem("BITBUCKET_BUILD_NUMBER") {
		a.logLady.Trace("BitBucket usage")
		return a.getUserAgent("bitbucket", callTree)
	}
	if checkForCISystem("TRAVIS") {
		a.logLady.Trace("TravisCI usage")
		return a.getUserAgent("travis-ci", callTree)
	}
	if checkForCISystem("GITLAB_CI") {
		a.logLady.Trace("GitLab usage")
		return a.getUserAgent("gitlab-ci", callTree)
	}
	if internal.CheckIfJenkins() {
		a.logLady.Trace("Jenkins usage")
		return a.getUserAgent("jenkins", callTree)
	}
	if internal.CheckIfGitHub() {
		id := getGitHubActionID()
		a.logLady.WithField("gh_action_id", id).Trace("GitHub Actions usage")
		return a.getUserAgent(fmt.Sprintf("github-action %s", id), callTree)
	}

	a.logLady.Trace("Returning User Agent")
	return a.getUserAgent("ci usage", callTree)
}

func (a *Agent) getUserAgent(agent string, callTree string) (userAgent string) {
	a.logLady.Trace("Obtaining parsed User Agent string")
	userAgent = fmt.Sprintf("%s (%s; %s %s; %s)", a.getUserAgentBaseAndVersion(), agent, a.Options.GoOS, a.Options.GoArch, callTree)
	a.logLady.WithField("user_agent_parsed", userAgent).Trace("Obtained parsed User Agent string")
	return
}

// Returns info from SC_CALLER_INFO, example: bitbucket-nancy-pipe-0.1.9
func getCallerInfo() string {
	s := os.Getenv("SC_CALLER_INFO")
	return s
}

func getGitHubActionID() string {
	s := os.Getenv("GITHUB_ACTION")
	return s
}

func checkForCISystem(system string) bool {
	s := os.Getenv(system)
	return s != ""
}
