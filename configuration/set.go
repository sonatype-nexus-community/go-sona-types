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
	"bufio"
	"fmt"
	"github.com/sirupsen/logrus"
	"github.com/sonatype-nexus-community/go-sona-types/internal"
	"github.com/sonatype-nexus-community/go-sona-types/ossindex/types"
	"gopkg.in/yaml.v2"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// For use when overriding Viper config type, e.g.: viper.SetConfigType(ConfigTypeYaml)
//
//goland:noinspection GoUnusedConst
const ConfigTypeYaml = "yaml"

// must match OSSIndexConfig.Username yaml tag. for use where tag name matters, like viper
const ViperKeyUsername = "ossi.Username"

// must match OSSIndexConfig.Token yaml tag. for use where tag name matters, like viper
const ViperKeyToken = "ossi.Token"

// OSSIndexConfig is a struct for holding OSS Index Configuration, and for writing it to yaml
type OSSIndexConfig struct {
	Username string `yaml:"Username"`
	Token    string `yaml:"Token"`
}

// Used when writing/reading OSS Index config to/from yaml files
type ConfMarshallOssi struct {
	Ossi OSSIndexConfig
}

// must match IQConfig.IQServer yaml tag. for use where tag name matters, like viper
const ViperKeyIQServer = "iq.Server"

// must match IQConfig.IQUsername yaml tag. for use where tag name matters, like viper
const ViperKeyIQUsername = "iq.Username"

// must match IQConfig.IQToken yaml tag. for use where tag name matters, like viper
const ViperKeyIQToken = "iq.Token"

// IQConfig is a struct for holding IQ Configuration, and for writing it to yaml
type IQConfig struct {
	IQServer   string `yaml:"Server"`
	IQUsername string `yaml:"Username"`
	IQToken    string `yaml:"Token"`
}

// Used when writing/reading IQ Server config to/from yaml files
type ConfMarshallIq struct {
	Iq IQConfig
}

type ConfigSet struct {
	logLady *logrus.Logger
	// HomeDir is exported so that in testing it can be set to a location like /tmp
	HomeDir string
	// ConfigLocation is exported so that in testing it can be used to test if the file has been written properly
	ConfigLocation string
}

func New(logger *logrus.Logger) (configSet *ConfigSet, err error) {
	if logger == nil {
		err = fmt.Errorf("missing logger")
		return
	}

	homeDir, _ := os.UserHomeDir()
	configSet = &ConfigSet{logLady: logger, HomeDir: homeDir}
	return
}

const msgConfigNotSet = "warning: config not set"

// GetConfigFromCommandLine is a method to obtain IQ or OSS Index config from the command line,
// and then write it to disk.
func (i *ConfigSet) GetConfigFromCommandLine(stdin io.Reader) (err error) {
	i.logLady.Info("Starting process to obtain config from user")
	reader := bufio.NewReader(stdin)
	fmt.Print("Hi! What config can I help you set, IQ or OSS Index (values: iq, ossindex, enter for exit)? ")
	configType, _ := reader.ReadString('\n')

	switch str := strings.TrimSpace(configType); str {
	case "iq":
		i.logLady.Info("User chose to set IQ Config, moving forward")
		i.ConfigLocation = types.GetIQServerConfigFile(i.HomeDir)
		err = i.getAndSetIQConfig(reader)
	case "ossindex":
		i.logLady.Info("User chose to set OSS Index config, moving forward")
		i.ConfigLocation = types.GetOssIndexConfigFile(i.HomeDir)
		err = i.getAndSetOSSIndexConfig(reader)
	case "":
		return fmt.Errorf(msgConfigNotSet)
	default:
		i.logLady.Infof("User chose invalid config type: %s, will retry", str)
		fmt.Printf("Invalid value: %s, 'iq' and 'ossindex' are accepted values, try again!\n", str)
		err = i.GetConfigFromCommandLine(stdin)
	}

	if err != nil {
		i.logLady.Error(err)
		return
	}
	return
}

func (i *ConfigSet) getAndSetIQConfig(reader *bufio.Reader) (err error) {
	i.logLady.Info("Getting config for IQ Server from user")

	iqConfig := IQConfig{IQServer: "http://localhost:8070", IQUsername: "admin", IQToken: "admin123"}

	fmt.Print("What is the address of your Nexus IQ Server (default: http://localhost:8070)? ")
	server, _ := reader.ReadString('\n')
	iqConfig.IQServer = emptyOrDefault(server, iqConfig.IQServer)

	fmt.Print("What username do you want to authenticate as (default: admin)? ")
	username, _ := reader.ReadString('\n')
	iqConfig.IQUsername = emptyOrDefault(username, iqConfig.IQUsername)

	fmt.Print("What token do you want to use (default: admin123)? ")
	token, _ := reader.ReadString('\n')
	iqConfig.IQToken = emptyOrDefault(token, iqConfig.IQToken)

	if iqConfig.IQUsername == "admin" || iqConfig.IQToken == "admin123" {
		i.logLady.Info("Warning user of bad life choices, using default values for IQ Server username or token")
		warnUserOfBadLifeChoices()
		fmt.Print("[y/N]? ")
		theChoice, _ := reader.ReadString('\n')
		theChoice = emptyOrDefault(theChoice, "N")
		if theChoice == "y" {
			i.logLady.Info("User chose to rectify their bad life choices, asking for config again")
			err = i.getAndSetIQConfig(reader)
		} else {
			i.logLady.Info("Successfully got IQ Server config from user, attempting to save to disk")
			err = i.marshallAndWriteToDisk(ConfMarshallIq{Iq: iqConfig})
		}
	} else {
		i.logLady.Info("Successfully got IQ Server config from user, attempting to save to disk")
		err = i.marshallAndWriteToDisk(ConfMarshallIq{Iq: iqConfig})
	}

	if err != nil {
		i.logLady.Error(err)
		return
	}
	return
}

func emptyOrDefault(value string, defaultValue string) string {
	str := strings.Trim(strings.TrimSpace(value), "\n")
	if str == "" {
		return defaultValue
	}
	return str
}

func (i *ConfigSet) getAndSetOSSIndexConfig(reader *bufio.Reader) (err error) {
	i.logLady.Info("Getting config for OSS Index from user")

	ossIndexConfig := OSSIndexConfig{}

	fmt.Print("What username do you want to authenticate as (ex: admin)? ")
	ossIndexConfig.Username, _ = reader.ReadString('\n')
	ossIndexConfig.Username = strings.Trim(strings.TrimSpace(ossIndexConfig.Username), "\n")

	fmt.Print("What token do you want to use? ")
	ossIndexConfig.Token, _ = reader.ReadString('\n')
	ossIndexConfig.Token = strings.Trim(strings.TrimSpace(ossIndexConfig.Token), "\n")

	i.logLady.Info("Successfully got OSS Index config from user, attempting to save to disk")
	err = i.marshallAndWriteToDisk(ConfMarshallOssi{Ossi: ossIndexConfig})
	if err != nil {
		i.logLady.Error(err)
		return
	}

	return
}

func (i *ConfigSet) marshallAndWriteToDisk(config interface{}) (err error) {
	d, err := yaml.Marshal(config)
	if err != nil {
		return err
	}

	base := filepath.Dir(i.ConfigLocation)

	if _, err = os.Stat(base); os.IsNotExist(err) {
		err = os.Mkdir(base, os.ModePerm)
		if err != nil {
			return
		}
	}

	err = os.WriteFile(i.ConfigLocation, d, 0644)
	if err != nil {
		return
	}

	i.logLady.WithField("config_location", i.ConfigLocation).Info("Successfully wrote config to disk")
	fmt.Printf("Successfully wrote config to: %s\n", i.ConfigLocation)
	return
}

func warnUserOfBadLifeChoices() {
	fmt.Println()
	fmt.Println("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
	fmt.Println("!!!! WARNING : You are using the default username and/or password for Nexus IQ. !!!!")
	fmt.Println("!!!! You are strongly encouraged to change these, and use a token.              !!!!")
	fmt.Println("!!!! Would you like to change them and try again?                               !!!!")
	fmt.Println("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
	fmt.Println()
}

func SkipUpdateByDefault() bool {
	// skip update when running on CI server, or if SKIP_UPDATE_CHECK env var is set
	return internal.CheckForCIEnvironment() || os.Getenv("SKIP_UPDATE_CHECK") == "true"
}
