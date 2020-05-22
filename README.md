# Go Sonatypes

This project is a nice lil set of libraries that we created for working with:

- Sonatype's OSS Index
- Sonatype's Nexus IQ Server
- Building different types of CycloneDX SBOMs
- Obtaining a User Agent for communicating with different services

A lot of our projects were starting to depend heavily on `nancy`, and it was slowing the pace of development on `nancy` down quite a bit, as well as making importing `nancy` a bit of a kitchen sink if you wanted to use some of it's libraries. Thusly, `go-sona-types` is born! The name is credited to @zendern or @fitzoh, who are good with puns!

## Development

You'll need Go 1.14, and that's about it!

Everything can be run with `make` locally.
