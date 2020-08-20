# Go Sonatypes

<a href="https://circleci.com/gh/sonatype-nexus-community/go-sona-types"><img src="https://circleci.com/gh/sonatype-nexus-community/go-sona-types.svg?style=shield" alt="Circle CI Build Status"></img></a>

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

// Obtains a pointer to a Server struct, with rational defaults set
ossi := ossindex.Default(logger)

// Obtains a pointer to a Server struct, with options you set
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

// Obtains a pointer to a Server struct
iq := iq.New(logger, iq.Options{Username: "username", Token: "token"})

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

#### User Agent

```golang
// Setup fake logger, use a real one when you consume this package
logger, _ := logrus.NewNullLogger()

// Obtains a pointer to aa Agent struct, useful in testing or if you need to override ClientTool or Version
ua := useragent.New(logger, useragent.Options{ClientTool: "your-client-tool", Version: "1.0.0", GoOS: runtime.GOOS, GoArch: runtime.GOARCH})

// Can be used to get aa Agent struct populated with defaults
ua = useragent.Default(logger)

// Obtains a properly formatted user-agent string for communicating with OSS Index or Nexus IQ Server
useragent := ua.GetUserAgent()
```

### Release Process

Follow the steps below to release a new version.

  1. Checkout/pull the latest `master` branch, and create a new tag with the desired semantic version and a helpful note:
  
         git tag -a v0.0.x -m "Helpful message in tag."
         
  2. Push the tag up:
  
         git push origin v0.0.x
         
  3. Click the GitHub buttons to make a new release from this new tag. 
