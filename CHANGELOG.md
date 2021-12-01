# ChangeLog

This format is based on [Keep a Changelog](https://keepachangelog.com/)
and this project adheres to [Semantic Versioning](https://semver.org).

## [0.2.0] - 2021-12-01

Added support for wintun 0.14.

### Breaking Changes

- Wintun driver versions before `0.14` are no longer support due to beraking
changes in che CAPI

### Fixed- 

## [0.1.5] - 2021-08-27

### Fixed

- Readme on crates.io

## [0.1.4] - 2021-08-27

### Added
- `panic_on_unsent_packets` feature flag to help in debugging ring buffer blockage issues

## [0.1.3] - 2021-06-28

### Fixed

- Cargo.toml metadata to include `package.metadata.docs.rs.default-target`.
Fixes build issue on docs.rs (we can only build docs on windows, 0.1.1 doesn't work)

## [0.1.2] - 2021-06-28
docs.rs testing

## [0.1.1] - 2021-06-28

- Cargo.toml metadata to build on linux

## [0.1.0] - 2021-06-28

First release with initial api
