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
