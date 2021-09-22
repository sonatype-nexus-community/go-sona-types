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
	"path/filepath"
	"time"

	"github.com/shopspring/decimal"
)

const (
	// Parent directory containing the OssIndex configuration file.
	// Intended for use with the user home directory.
	OssIndexDirName = ".ossindex"

	// Name of the file containing OssIndex configuration settings.
	// Typically found in directory OssIndexDirName.
	OssIndexConfigFileName = ".oss-index-config"

	// Parent directory containing the IQ Server configuration file.
	// Intended for use with the user home directory.
	IQServerDirName = ".iqserver"

	// Name of the file containing IQ Server configuration settings.
	// Typically found in directory IQServerDirName.
	IQServerConfigFileName = ".iq-server-config"
)

// Parent directory containing the OssIndex configuration file.
func GetOssIndexDirectory(homeDir string) string {
	return filepath.Join(homeDir, OssIndexDirName)
}

// Path to the file containing OssIndex configuration settings.
func GetOssIndexConfigFile(homeDir string) string {
	return filepath.Join(GetOssIndexDirectory(homeDir), OssIndexConfigFileName)
}

// Parent directory containing the IQ Server configuration file.
func GetIQServerDirectory(homeDir string) string {
	return filepath.Join(homeDir, IQServerDirName)
}

// Path to the file containing IQ Server configuration settings.
func GetIQServerConfigFile(homeDir string) string {
	return filepath.Join(GetIQServerDirectory(homeDir), IQServerConfigFileName)
}

type Options struct {
	Version     string
	CleanCache  bool
	Username    string
	Token       string
	Tool        string
	OSSIndexURL string
	DBCacheName string
	DBCachePath string
	TTL         time.Time
}

type Coordinate struct {
	Coordinates     string
	Reference       string
	Vulnerabilities []Vulnerability
	InvalidSemVer   bool
}

type Vulnerability struct {
	ID          string
	Title       string
	Description string
	CvssScore   decimal.Decimal
	CvssVector  string
	Cve         string
	Reference   string
	Excluded    bool
}

func (c Coordinate) IsVulnerable() bool {
	for _, v := range c.Vulnerabilities {
		if !v.Excluded {
			return true
		}
	}
	return false
}

//Mark Excluded=true for all Vulnerabilities of the given Coordinate if their Title is in the list of exclusions
func (c *Coordinate) ExcludeVulnerabilities(exclusions []string) {
	for i := range c.Vulnerabilities {
		c.Vulnerabilities[i].maybeExcludeVulnerability(exclusions)
	}
}

//Mark the given vulnerability as excluded if it appears in the exclusion list
func (v *Vulnerability) maybeExcludeVulnerability(exclusions []string) {
	for _, ex := range exclusions {
		if v.Cve == ex || v.ID == ex {
			v.Excluded = true
		}
	}
}

type AuditRequest struct {
	Coordinates []string `json:"coordinates"`
}

// OSSIndexRateLimitError is a custom error implementation to allow us to return a better error response to the user
// as well as check the type of the error so we can surface this information.
type OSSIndexRateLimitError struct {
}

func (o *OSSIndexRateLimitError) Error() string {
	return `You have been rate limited by OSS Index.
If you do not have a OSS Index account, please visit https://ossindex.sonatype.org/user/register to register an account.
After registering and verifying your account, you can retrieve your username (Email Address), and API Token
at https://ossindex.sonatype.org/user/settings. Upon retrieving those, run 'nancy config', set your OSS Index
settings, and rerun Nancy.`
}

type OSSIndexError struct {
	Err     error
	Message string
}

func (o *OSSIndexError) Error() string {
	if o.Err != nil {
		return fmt.Sprintf("An error occurred: %s, err: %s", o.Message, o.Err.Error())
	}
	return fmt.Sprintf("An error occurred: %s", o.Message)
}
