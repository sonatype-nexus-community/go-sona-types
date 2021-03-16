//
// Copyright 2020-present Sonatype Inc.
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
package types

import (
	"fmt"
)

func ExampleGetOssIndexDirectory() {
	//typically: homeDir, _ := os.UserHomeDir()
	homeDir := "someHomeDir"
	configFile := GetOssIndexDirectory(homeDir)
	fmt.Println(configFile)
	// Output: someHomeDir/.ossindex
}

func ExampleGetOssIndexConfigFile() {
	//typically: homeDir, _ := os.UserHomeDir()
	homeDir := "someHomeDir"
	configFile := GetOssIndexConfigFile(homeDir)
	fmt.Println(configFile)
	// Output: someHomeDir/.ossindex/.oss-index-config
}

func ExampleGetIQServerDirectory() {
	//typically: homeDir, _ := os.UserHomeDir()
	homeDir := "someHomeDir"
	configFile := GetIQServerDirectory(homeDir)
	fmt.Println(configFile)
	// Output: someHomeDir/.iqserver
}

func ExampleGetIQServerConfigFile() {
	//typically: homeDir, _ := os.UserHomeDir()
	homeDir := "someHomeDir"
	configFile := GetIQServerConfigFile(homeDir)
	fmt.Println(configFile)
	// Output: someHomeDir/.iqserver/.iq-server-config
}
