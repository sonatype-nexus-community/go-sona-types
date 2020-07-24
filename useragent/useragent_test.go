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
	"os"
	"testing"

	"github.com/sirupsen/logrus/hooks/test"
)

func TestGetUserAgentNonCI(t *testing.T) {
	clearCircleCIVariables()
	expected := "nancy-client/development (non ci usage; linux amd64; )"

	ua := setupUserAgent(t)

	agent := ua.GetUserAgent()

	if agent != expected {
		t.Errorf("User Agent not retrieved successfully, got %s, expected %s", agent, expected)
	}
}

func TestGetUserAgentCircleCI(t *testing.T) {
	expected := "nancy-client/development (circleci; linux amd64; )"

	os.Setenv("CI", "true")
	os.Setenv("CIRCLECI", "true")

	ua := setupUserAgent(t)

	agent := ua.GetUserAgent()

	if agent != expected {
		t.Errorf("User Agent not retrieved successfully, got %s, expected %s", agent, expected)
	}
}

func TestGetUserAgentJenkins(t *testing.T) {
	clearCircleCIVariables()
	expected := "nancy-client/development (jenkins; linux amd64; )"

	os.Setenv("JENKINS_HOME", "/a/place/under/the/sun")

	ua := setupUserAgent(t)

	agent := ua.GetUserAgent()

	os.Unsetenv("JENKINS_HOME")

	if agent != expected {
		t.Errorf("User Agent not retrieved successfully, got %s, expected %s", agent, expected)
	}
}

func TestGetUserAgentTravisCI(t *testing.T) {
	clearCircleCIVariables()
	expected := "nancy-client/development (travis-ci; linux amd64; )"

	os.Setenv("CI", "true")
	os.Setenv("TRAVIS", "true")

	ua := setupUserAgent(t)

	agent := ua.GetUserAgent()

	os.Unsetenv("CI")
	os.Unsetenv("TRAVIS")

	if agent != expected {
		t.Errorf("User Agent not retrieved successfully, got %s, expected %s", agent, expected)
	}
}

func TestGetUserAgentGitLabCI(t *testing.T) {
	clearCircleCIVariables()
	expected := "nancy-client/development (gitlab-ci; linux amd64; )"

	os.Setenv("CI", "true")
	os.Setenv("GITLAB_CI", "true")

	ua := setupUserAgent(t)

	agent := ua.GetUserAgent()

	os.Unsetenv("CI")
	os.Unsetenv("GITLAB_CI")

	if agent != expected {
		t.Errorf("User Agent not retrieved successfully, got %s, expected %s", agent, expected)
	}
}

func TestGetUserAgentGitHubAction(t *testing.T) {
	clearCircleCIVariables()
	expected := "nancy-client/development (github-action 20; linux amd64; )"

	os.Setenv("GITHUB_ACTIONS", "true")
	os.Setenv("GITHUB_ACTION", "20")

	ua := setupUserAgent(t)

	agent := ua.GetUserAgent()

	os.Unsetenv("GITHUB_ACTIONS")
	os.Unsetenv("GITHUB_ACTION")

	if agent != expected {
		t.Errorf("User Agent not retrieved successfully, got %s, expected %s", agent, expected)
	}
}

func TestGetUserAgentBitBucket(t *testing.T) {
	clearCircleCIVariables()
	expected := "nancy-client/development (bitbucket; linux amd64; )"

	os.Setenv("CI", "true")
	os.Setenv("BITBUCKET_BUILD_NUMBER", "20")

	ua := setupUserAgent(t)

	agent := ua.GetUserAgent()

	os.Unsetenv("CI")
	os.Unsetenv("BITBUCKET_BUILD_NUMBER")

	if agent != expected {
		t.Errorf("User Agent not retrieved successfully, got %s, expected %s", agent, expected)
	}
}

func TestGetUserAgentScCallerInfo(t *testing.T) {
	clearCircleCIVariables()
	expected := "nancy-client/development (non ci usage; linux amd64; bitbucket-nancy-pipe-0.1.9)"

	os.Setenv("SC_CALLER_INFO", "bitbucket-nancy-pipe-0.1.9")

	ua := setupUserAgent(t)

	agent := ua.GetUserAgent()

	os.Unsetenv("SC_CALLER_INFO")

	if agent != expected {
		t.Errorf("User Agent not retrieved successfully, got %s, expected %s", agent, expected)
	}
}

func TestGetUserAgentCINoClueWhatSystem(t *testing.T) {
	clearCircleCIVariables()
	expected := "nancy-client/development (ci usage; linux amd64; )"

	os.Setenv("CI", "true")
	ua := setupUserAgent(t)

	agent := ua.GetUserAgent()

	os.Unsetenv("CI")

	if agent != expected {
		t.Errorf("User Agent not retrieved successfully, got %s, expected %s", agent, expected)
	}
}

func clearCircleCIVariables() {
	os.Unsetenv("CI")
	os.Unsetenv("CIRCLECI")
}

func setupUserAgent(t *testing.T) *Agent {
	logger, _ := test.NewNullLogger()
	options := Options{
		ClientTool: "nancy-client",
		Version:    "development",
		GoOS:       "linux",
		GoArch:     "amd64",
	}
	return New(logger, options)
}

// use compiler to ensure IAgent interface is implemented by Agent
var _ IAgent = (*Agent)(nil)
