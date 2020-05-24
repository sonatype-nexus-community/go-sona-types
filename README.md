# Go Sonatypes

This project is a nice lil set of libraries that we created for working with:

- Sonatype's OSS Index
- Sonatype's Nexus IQ Server
- Building different types of CycloneDX SBOMs
- Obtaining a User Agent for communicating with different services

A lot of our projects were starting to depend heavily on `nancy`, and it was slowing the pace of development on `nancy` down quite a bit, as well as making importing `nancy` a bit of a kitchen sink if you wanted to use some of it's libraries. Thusly, `go-sona-types` is born! The name is credited to @zendern or @fitzoh, who are good with puns!

## Development

You'll need Go 1.14, and that's about it!

Everything (tests, lint, etc...) can be run with `make` locally.

### Usage

This section is only created for suggested use of each package.

#### OSS Index

```golang
// Setup fake logger, use a real one when you consume this package
logger, _ := logrus.NewNullLogger()

// Obtains a pointer to an OSSIndex struct, with rational defaults set
ossi := ossindex.Default(logger)

// Obtains a pointer to an OSSIndex struct, with options you set
ossi = ossindex.New(loggger, types.Options{Username: "username", Token: "token"})

// Audits a slice of purls, returns results or an error
results, err := ossi.AuditPackages([]string{"a", "list", "of", "purls"})

// Removes database cache
err = ossi.NoCacheNoProblems()
```

#### IQ Server

```golang
// Setup fake logger, use a real one when you consume this package
logger, _ := logrus.NewNullLogger()

// Obtains a pointer to a IQServer struct
iq := iq.New(logger, types.Options{Username: "username", Token: "token"})

// Audits a slice of purls, given a public IQ Server application ID, and returns results or an error
results, err := iq.AuditPackages([]string{"a", "list", "of", "purls"}, "public-application-id")
```

#### CycloneDX

```golang
// Setup fake logger, use a real one when you consume this package
logger, _ := logrus.NewNullLogger()

// Obtains a pointer to a CycloneDX struct
sbom := cyclonedx.Default(logger)

// Obtains a SBOM from []types.Coordinates
results := sbom.FromCoordinates([]types.Coordinates{})
```
