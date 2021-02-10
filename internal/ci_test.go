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
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestTestEnvVar_TestingNil(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			err, ok := r.(error)
			if !ok {
				assert.Fail(t, "expected panic due to missing testing parameter")
			}
			assert.Equal(t, "missing unit test reference", err.Error())
		} else {
			assert.Fail(t, "expected panic due nil testing parameter")
		}
	}()
	NewTestEnvVar(nil, "blah")
}

func TestTestEnvVar_NameNil(t *testing.T) {
	mockT := &testing.T{}
	NewTestEnvVar(mockT, "")
	assert.True(t, mockT.Failed(), "expected failure due to missing name parameter")
}

func verifyEnvVarAffectsCIDetection(t *testing.T, envVar *TestEnvVar) {
	defer func() {
		envVar.Reset()
	}()

	envVar.Unset()
	assert.Equal(t, false, CheckForCIEnvironment(), envVar)

	envVar.Set("true")
	assert.Equal(t, true, CheckForCIEnvironment(), envVar)
	envVar.Unset()
}

func TestCheckForCIEnvironment(t *testing.T) {
	envCI := NewTestEnvVar(t, "CI")
	verifyEnvVarAffectsCIDetection(t, envCI)
	// clear CI var so later tests can pass when running in our real CI environment. Chicken/Egg
	envCI.Unset()
	defer envCI.Reset()

	verifyEnvVarAffectsCIDetection(t, NewTestEnvVar(t, "JENKINS_HOME"))
	verifyEnvVarAffectsCIDetection(t, NewTestEnvVar(t, "GITHUB_ACTIONS"))
}
