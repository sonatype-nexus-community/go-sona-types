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

// Functions for detecting various CI environment side effects
package internal

import (
	"fmt"
	"os"
	"testing"
)

func CheckForCIEnvironment() bool {
	s := os.Getenv("CI")
	if s != "" {
		return true
	}
	return CheckIfJenkins() || CheckIfGitHub()
}

func CheckIfJenkins() bool {
	s := os.Getenv("JENKINS_HOME")
	return s != ""
}

func CheckIfGitHub() bool {
	s := os.Getenv("GITHUB_ACTIONS")
	return s != ""
}

// This TestEnvVar stuff below is intended for use only as testing utilities.
// It lives here (under an "internal" package) so it is accessible by test code in this project.
type TestEnvVar struct {
	t             *testing.T
	name          string
	wasPresent    bool
	originalValue string
}

func NewTestEnvVar(t *testing.T, name string) *TestEnvVar {
	if t == nil {
		panic(fmt.Errorf("missing unit test reference"))
	}
	et := TestEnvVar{}
	et.t = t
	if name == "" {
		et.t.Error("missing environment variable name")
	}
	et.name = name
	et.originalValue, et.wasPresent = os.LookupEnv(et.name)
	return &et
}

func (et *TestEnvVar) Set(newValue string) {
	if err := os.Setenv(et.name, newValue); err != nil {
		et.t.Errorf("failed to set environment variable: %s to value: %s", et.name, newValue)
	}
}

func (et *TestEnvVar) Unset() {
	if err := os.Unsetenv(et.name); err != nil {
		et.t.Errorf("failed to clear environment variable: %s", et.name)
	}
}

func (et *TestEnvVar) Reset() {
	if et.wasPresent {
		et.Set(et.originalValue)
	} else {
		et.Unset()
	}
}
