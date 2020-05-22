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

// Package cyclonedx has definitions and functions for processing golang purls into a minimal CycloneDX 1.1 Sbom
package cyclonedx

import (
	"encoding/xml"
	"fmt"
	"strings"

	"github.com/shopspring/decimal"
	"github.com/sirupsen/logrus"
	"github.com/sonatype-nexus-community/go-sona-types/ossindex/types"

	"github.com/package-url/packageurl-go"
)

// CycloneDX Types

// Sha1SBOM is a struct to begin assembling a minimal SBOM based on sha1s
type Sha1SBOM struct {
	Location string
	Sha1     string
}

// Sbom is a struct to begin assembling a minimal SBOM
type Sbom struct {
	XMLName    xml.Name   `xml:"bom"`
	Xmlns      string     `xml:"xmlns,attr"`
	XMLNSV     string     `xml:"xmlns:v,attr"`
	Version    string     `xml:"version,attr"`
	Components Components `xml:"components"`
}

// Components is a struct to list the components in a SBOM
type Components struct {
	Component []Component `xml:"component"`
}

// Component is a struct to list the properties of a component in a SBOM
type Component struct {
	Type            string          `xml:"type,attr"`
	BomRef          string          `xml:"bom-ref,attr"`
	Name            string          `xml:"name"`
	Version         string          `xml:"version"`
	Group           string          `xml:"group,omitempty"`
	Purl            string          `xml:"purl,omitempty"`
	Hashes          *Hashes         `xml:"hashes,omitempty"`
	Vulnerabilities Vulnerabilities `xml:"v:vulnerabilities,omitempty"`
}

type Hashes struct {
	Hash []Hash `xml:"hash,omitempty"`
}

type Hash struct {
	Alg       string `xml:"alg,attr,omitempty"`
	Attribute string `xml:",chardata"`
}

type Vulnerabilities struct {
	Vulnerability []SbomVulnerability `xml:"v:vulnerability,omitempty"`
}

type SbomVulnerability struct {
	Ref         string    `xml:"ref,attr,omitempty"`
	ID          string    `xml:"v:id"`
	Source      Source    `xml:"v:source"`
	Ratings     []Ratings `xml:"v:ratings"`
	Description string    `xml:"v:description"`
}

type Ratings struct {
	Rating Rating `xml:"v:rating"`
}

type Rating struct {
	Score    Score  `xml:"v:score,omitempty"`
	Severity string `xml:"v:severity,omitempty"`
	Method   string `xml:"v:method,omitempty"`
	Vector   string `xml:"v:vector,omitempty"`
}

type Score struct {
	Base           decimal.Decimal `xml:"v:base,omitempty"`
	Impact         string          `xml:"v:impact,omitempty"`
	Exploitability string          `xml:"v:exploitability,omitempty"`
}

type Source struct {
	Name string `xml:"name,attr"`
	URL  string `xml:"v:url"`
}

type CycloneDXError struct {
	Err     error
	Message string
}

func (c *CycloneDXError) Error() string {
	return fmt.Sprintf("An error occurred: %s, err: %e", c.Message, c.Err)
}

const cycloneDXBomXmlns1_1 = "http://cyclonedx.org/schema/bom/1.1"
const cycloneDXBomXmlns1_0V = "http://cyclonedx.org/schema/ext/vulnerability/1.0"

const version = "1"

var logLady *logrus.Logger

// ProcessPurlsIntoSBOM will take a slice of packageurl.PackageURL and convert them
// into a minimal 1.1 CycloneDX sbom
func ProcessPurlsIntoSBOM(results []types.Coordinate, logger *logrus.Logger) string {
	logLady = logger
	return processPurlsIntoSBOMSchema1_1(results)
}

// SBOMFromPackageURLs will take a slice of packageurl.PackageURL and convert them
// into a minimal 1.1 CycloneDX sbom
func SBOMFromPackageURLs(results []packageurl.PackageURL, logger *logrus.Logger) string {
	logLady = logger
	return processPackageURLsIntoSBOMSchema1_1(results)
}

// SBOMFromSHA1 will take a slice of Sha1SBOM and convert them
// into a minimal 1.1 CycloneDX sbom
func SBOMFromSHA1(results []Sha1SBOM, logger *logrus.Logger) string {
	logLady = logger
	return createMinimalSha1Sbom(results)
}

func createMinimalSha1Sbom(results []Sha1SBOM) string {
	sbom := createSbomDocument()
	for _, v := range results {
		component := Component{
			Type:    "library",
			BomRef:  v.Sha1,
			Name:    v.Location,
			Version: "0",
		}

		hashes := Hashes{}

		hashes.Hash = append(hashes.Hash, Hash{Alg: "SHA-1", Attribute: v.Sha1})

		component.Hashes = &hashes

		sbom.Components.Component = append(sbom.Components.Component, component)
	}

	return processAndReturnSbom(sbom)
}

func processPackageURLsIntoSBOMSchema1_1(results []packageurl.PackageURL) string {
	sbom := createSbomDocument()
	for _, v := range results {
		component := Component{
			Type:    "library",
			BomRef:  v.ToString(),
			Purl:    v.ToString(),
			Name:    v.Name,
			Version: v.Version,
		}

		sbom.Components.Component = append(sbom.Components.Component, component)
	}

	return processAndReturnSbom(sbom)
}

func processPurlsIntoSBOMSchema1_1(results []types.Coordinate) string {
	sbom := createSbomDocument()
	for _, v := range results {
		purl, err := packageurl.FromString(v.Coordinates)
		if err != nil {
			_ = &CycloneDXError{
				Err:     err,
				Message: "Error parsing purl from given coordinate",
			}
			return ""
		}

		// IQ requires a v before versions, so add one if it doesn't exist
		if !strings.HasPrefix(purl.Version, "v") {
			purl.Version = fmt.Sprintf("v%s", purl.Version)
		}

		component := Component{
			Type:    "library",
			BomRef:  purl.String(),
			Purl:    purl.String(),
			Name:    purl.Name,
			Version: purl.Version,
		}

		if v.IsVulnerable() {
			vulns := Vulnerabilities{}
			for _, x := range v.Vulnerabilities {
				rating := Rating{Score: Score{Base: x.CvssScore}}
				rating.Vector = x.CvssVector
				ratings := Ratings{}
				ratings.Rating = rating
				source := Source{Name: "ossindex"}
				source.URL = x.Reference
				vuln := SbomVulnerability{ID: x.Cve, Source: source, Description: x.Description, Ref: v.Coordinates}
				vuln.Ratings = append(vuln.Ratings, ratings)
				vulns.Vulnerability = append(vulns.Vulnerability, vuln)
			}
			component.Vulnerabilities = vulns
		}

		sbom.Components.Component = append(sbom.Components.Component, component)
	}

	return processAndReturnSbom(sbom)
}

func createSbomDocument() *Sbom {
	sbom := Sbom{}
	sbom.Xmlns = cycloneDXBomXmlns1_1
	sbom.XMLNSV = cycloneDXBomXmlns1_0V
	sbom.Version = version

	return &sbom
}

func processAndReturnSbom(sbom *Sbom) string {
	output, err := xml.MarshalIndent(sbom, " ", "     ")
	if err != nil {
		logLady.Error(err)
	}

	output = []byte(xml.Header + string(output))

	return string(output)
}
