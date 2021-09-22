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

// Package cache has definitions and functions for processing the OSS Index Feed
package cache

import (
	"testing"
	"time"

	"github.com/shopspring/decimal"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/sonatype-nexus-community/go-sona-types/ossindex/types"
	"github.com/stretchr/testify/assert"
)

var coordinates []types.Coordinate

var purls []string

func TestWithCacheBasePath(t *testing.T) {
	// This is going to act wonky on Windows, but should be fine since we do majority of our dev, etc... on OS X and Linux
	cache := setupTestsAndCache(t, "/tmp")

	err := cache.Insert(coordinates)
	assert.Nil(t, err)

	var result DBValue
	err = cache.getKeyAndHydrate(coordinates[0].Coordinates, &result)

	assert.Equal(t, coordinates[0], result.Coordinates)
	assert.Nil(t, err)

	tearDown(t, cache)
}

func TestInsert(t *testing.T) {
	cache := setupTestsAndCache(t, "")

	err := cache.Insert(coordinates)
	assert.Nil(t, err)

	var result DBValue
	err = cache.getKeyAndHydrate(coordinates[0].Coordinates, &result)

	assert.Equal(t, coordinates[0], result.Coordinates)
	assert.Nil(t, err)

	tearDown(t, cache)
}

func TestGetWithRegularTTL(t *testing.T) {
	cache := setupTestsAndCache(t, "")

	err := cache.Insert(coordinates)
	assert.Nil(t, err)

	newPurls, results, err := cache.GetCacheValues(purls)

	assert.Empty(t, newPurls)
	assert.Equal(t, results, coordinates)
	assert.Nil(t, err)

	tearDown(t, cache)
}

func TestGetWithExpiredTTL(t *testing.T) {
	cache := setupTestsAndCache(t, "")
	cache.Options.TTL = time.Now().AddDate(0, 0, -1)

	err := cache.Insert(coordinates)
	assert.Nil(t, err)

	newPurls, results, err := cache.GetCacheValues(purls)

	assert.Equal(t, purls, newPurls)
	assert.Empty(t, results)
	assert.Nil(t, err)

	var result DBValue
	err = cache.getKeyAndHydrate(purls[0], &result)
	assert.NotNil(t, err)
	assert.Equal(t, err.Error(), "Error: key not found")

	tearDown(t, cache)
}

func setupTestsAndCache(t *testing.T, dbCachePath string) *Cache {
	dec, _ := decimal.NewFromString("9.8")
	coordinate := types.Coordinate{
		Coordinates: "pkg:golang/test@0.0.0",
		Reference:   "http://www.innernet.com",
		Vulnerabilities: []types.Vulnerability{
			{
				ID:          "id",
				Title:       "test",
				Description: "description",
				CvssScore:   dec,
				CvssVector:  "vectorvictor",
				Cve:         "CVE-123-123",
				Reference:   "http://www.internet.com",
				Excluded:    false,
			},
		},
	}

	purls = append(purls, "pkg:golang/test@0.0.0")

	coordinates = append(coordinates, coordinate)
	logger, _ := test.NewNullLogger()
	options := Options{DBName: "nancy-cache-test", TTL: time.Now().Local().Add(time.Hour * 12)}
	if dbCachePath != "" {
		options.DBCachePath = dbCachePath
	}

	cache := New(logger, options)
	err := cache.RemoveCache()
	if err != nil {
		t.Error(err)
	}
	return cache
}

func tearDown(t *testing.T, cache *Cache) {
	err := cache.RemoveCache()
	if err != nil {
		t.Error(err)
	}
}
