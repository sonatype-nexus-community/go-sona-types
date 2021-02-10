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

package configuration

import (
	"bytes"
	"fmt"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"os"
	"strings"
	"testing"
)

func setup(t *testing.T) (configSet *ConfigSet) {
	logger, _ := test.NewNullLogger()
	configSet, err := New(logger)
	assert.Nil(t, err)
	configSet.HomeDir = "/tmp"
	return
}

func TestGetConfigFromCommandLineLoggerNil(t *testing.T) {
	badConfig, err := New(nil)
	assert.Error(t, err)
	assert.Equal(t, "missing logger", err.Error())
	assert.Nil(t, badConfig)
}

var (
	configSet *ConfigSet
)

func TestGetConfigFromCommandLineInvalidConfigType(t *testing.T) {
	var buffer bytes.Buffer
	buffer.Write([]byte("badconfigtype\ntestuser\ntoken\n"))

	configSet = setup(t)
	err := configSet.GetConfigFromCommandLine(&buffer)
	assert.Error(t, err)
	assert.Equal(t, msgConfigNotSet, err.Error())
}

func TestGetConfigFromCommandLineOssIndex(t *testing.T) {
	var buffer bytes.Buffer
	buffer.Write([]byte("ossindex\ntestuser\ntoken\n"))

	configSet = setup(t)
	err := configSet.GetConfigFromCommandLine(&buffer)
	if err != nil {
		t.Errorf("Test failed: %s", err.Error())
	}

	b, err := ioutil.ReadFile(configSet.ConfigLocation)
	if err != nil {
		t.Errorf("Test failed: %s", err.Error())
	}

	var confMarshallOssi ConfMarshallOssi
	err = yaml.Unmarshal(b, &confMarshallOssi)
	if err != nil {
		t.Errorf("Test failed: %s", err.Error())
	}

	if confMarshallOssi.Ossi.Username != "testuser" && confMarshallOssi.Ossi.Token != "token" {
		t.Errorf("Config not set properly, expected 'testuser' && 'token' but got '%s' and '%s'", confMarshallOssi.Ossi.Username, confMarshallOssi.Ossi.Token)
	}

	// since we have the file bytes, also verify the ViperKey strings
	content := string(b)
	verifyYamlLine(t, content, ViperKeyUsername, "testuser")
	verifyYamlLine(t, content, ViperKeyToken, "token")
}

func verifyYamlLine(t *testing.T, content string, viperKey string, expectedValue string) {
	yamlPrefix := viperKey[:strings.Index(viperKey, ".")]
	println(yamlPrefix)

	// no harm in re-testing yaml header each time
	if !strings.HasPrefix(content, yamlPrefix+":") {
		t.Errorf("wrong config yaml")
	}

	expectedYamlLine := "  " + strings.TrimPrefix(viperKey, yamlPrefix+".") + ": " + expectedValue
	assert.Contains(t, content, expectedYamlLine)
}

func TestGetConfigFromCommandLineIqServer(t *testing.T) {
	var buffer bytes.Buffer
	buffer.Write([]byte("iq\nhttp://localhost:8070\nadmin\nadmin123\nn"))

	configSet = setup(t)
	err := configSet.GetConfigFromCommandLine(&buffer)
	if err != nil {
		t.Errorf("Test failed: %s", err.Error())
	}

	b, err := ioutil.ReadFile(configSet.ConfigLocation)
	if err != nil {
		t.Errorf("Test failed: %s", err.Error())
	}

	var confMarshallIq ConfMarshallIq
	err = yaml.Unmarshal(b, &confMarshallIq)
	if err != nil {
		t.Errorf("Test failed: %s", err.Error())
	}

	if confMarshallIq.Iq.IQUsername != "admin" && confMarshallIq.Iq.IQToken != "admin123" && confMarshallIq.Iq.IQServer != "http://localhost:8070" {
		t.Errorf("Config not set properly, expected 'admin', 'admin123' and 'http://localhost:8070' but got %s, %s and %s", confMarshallIq.Iq.IQUsername, confMarshallIq.Iq.IQToken, confMarshallIq.Iq.IQServer)
	}

	// since we have the file bytes, also verify the ViperKey strings
	content := string(b)
	verifyYamlLine(t, content, ViperKeyIQServer, "http://localhost:8070")
	verifyYamlLine(t, content, ViperKeyIQUsername, "admin")
	verifyYamlLine(t, content, ViperKeyIQToken, "admin123")
}

func TestGetConfigFromCommandLineIqServerRectifyBadChoicesDefault(t *testing.T) {
	var buffer bytes.Buffer
	buffer.Write([]byte("iq\nhttp://localhost:8070\nadmin\nadmin123\n\n"))

	configSet = setup(t)
	err := configSet.GetConfigFromCommandLine(&buffer)
	if err != nil {
		t.Errorf("Test failed: %s", err.Error())
	}

	b, err := ioutil.ReadFile(configSet.ConfigLocation)
	if err != nil {
		t.Errorf("Test failed: %s", err.Error())
	}

	var confMarshallIq ConfMarshallIq
	err = yaml.Unmarshal(b, &confMarshallIq)
	if err != nil {
		t.Errorf("Test failed: %s", err.Error())
	}

	if confMarshallIq.Iq.IQUsername != "admin" && confMarshallIq.Iq.IQToken != "admin123" && confMarshallIq.Iq.IQServer != "http://localhost:8070" {
		t.Errorf("Config not set properly, expected 'admin', 'admin123' and 'http://localhost:8070' but got %s, %s and %s", confMarshallIq.Iq.IQUsername, confMarshallIq.Iq.IQToken, confMarshallIq.Iq.IQServer)
	}
}

func TestGetConfigFromCommandLineIqServerWithLoopToResetConfig(t *testing.T) {
	var buffer bytes.Buffer
	buffer.Write([]byte("iq\nhttp://localhost:8070\nadmin\nadmin123\ny\nhttp://localhost:8080\nadmin1\nadmin1234\n"))

	configSet = setup(t)
	err := configSet.GetConfigFromCommandLine(&buffer)
	if err != nil {
		t.Errorf("Test failed: %s", err.Error())
	}

	b, err := ioutil.ReadFile(configSet.ConfigLocation)
	if err != nil {
		t.Errorf("Test failed: %s", err.Error())
	}

	var confMarshallIq ConfMarshallIq
	err = yaml.Unmarshal(b, &confMarshallIq)
	if err != nil {
		t.Errorf("Test failed: %s", err.Error())
	}

	if confMarshallIq.Iq.IQUsername != "admin1" && confMarshallIq.Iq.IQToken != "admin1234" && confMarshallIq.Iq.IQServer != "http://localhost:8080" {
		t.Errorf("Config not set properly, expected 'admin1', 'admin1234' and 'http://localhost:8080' but got %s, %s and %s", confMarshallIq.Iq.IQUsername, confMarshallIq.Iq.IQToken, confMarshallIq.Iq.IQServer)
	}
}

type EnvVarTuple struct {
	t             *testing.T
	name          string
	wasPresent    bool
	originalValue string
}

func NewTestEnvVar(t *testing.T, name string) *EnvVarTuple {
	if t == nil {
		panic(fmt.Errorf("missing unit test reference"))
	}
	et := EnvVarTuple{}
	et.t = t
	if name == "" {
		et.t.Errorf("missing environment variable name")
	}
	et.name = name
	et.originalValue, et.wasPresent = os.LookupEnv(et.name)
	return &et
}

func (et *EnvVarTuple) set(newValue string) {
	if err := os.Setenv(et.name, newValue); err != nil {
		et.t.Errorf("failed to set environment variable: %s to value: %s", et.name, newValue)
	}
}

func (et *EnvVarTuple) unset() {
	if err := os.Unsetenv(et.name); err != nil {
		et.t.Errorf("failed to clear environment variable: %s", et.name)
	}
}

func (et *EnvVarTuple) reset() {
	if et.wasPresent {
		et.set(et.originalValue)
	} else {
		et.unset()
	}
}

func TestSkipUpdateByDefault(t *testing.T) {
	verifyEnvVarAffectsSkipUpdate(t, NewTestEnvVar(t, "CI"))
	verifyEnvVarAffectsSkipUpdate(t, NewTestEnvVar(t, "JENKINS_HOME"))
	verifyEnvVarAffectsSkipUpdate(t, NewTestEnvVar(t, "GITHUB_ACTIONS"))
}

func verifyEnvVarAffectsSkipUpdate(t *testing.T, eVarCI *EnvVarTuple) {
	defer func() {
		eVarCI.reset()
	}()

	eVarCI.unset()
	assert.Equal(t, false, SkipUpdateByDefault(), eVarCI)

	assert.Nil(t, os.Setenv(eVarCI.name, "true"))
	eVarCI.set("true")
	assert.Equal(t, true, SkipUpdateByDefault())
	eVarCI.unset()
}
