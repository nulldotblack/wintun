# ChangeLog

This format is based on [Keep a Changelog](https://keepachangelog.com/)
and this project adheres to [Semantic Versioning](https://semver.org).

## [0.4.0] - 2024-01-12

## Added
- `Adapter::get_mtu`, `set_dns_servers`, and `Adapter::get_active_network_interface_gateways`: https://github.com/nulldotblack/wintun/pull/13
- `Error::ShuttingDown`: https://github.com/nulldotblack/wintun/pull/14

### Breaking Changes
- Adding the `ShuttingDown` variant to `wintun::Error` breaks exhastive matches on previous versions. `wintun::Error` is now marked `#[non_exhaustive]` to make future additions backwards compatable

## [0.3.2] - 2023-09-27

## Added
- `Adapter::get_mtu`: https://github.com/nulldotblack/wintun/pull/11

### Changed
- Improved formatting of errors: https://github.com/nulldotblack/wintun/pull/11

## [0.3.1] - 2023-09-16

## Added
- Support for non 32bit x86 and arm targets in all three examples

### Updated
- Adapter docs

## [0.3.0] - 2023-09-15

### Added
- udp-echo example which mirrors packets via the tun interface
- `Adapter::get_name`, `Adapter::set_name`, and `Adapter::get_guid`
- `Adapter::set_address` `Adapter::set_gateway`, `Adapter::set_netmask`, or `Adapter::set_network_addresses_tuple` to set all three at once
  - Easily configure adapter address, netmask, and gateway properties to more easily control how it interacts with the Windows networking stack
- And `Adapter::get_addresses`, `Adapter::get_gateways`, `Adapter::get_netmask_of_address` to read this state

### Breaking Changes

- Renamed `enum ApiError` -> `enum Error` and added more variants.
  - All functions returning `wintun::Result` are effected.
- Removed `pool: &str` parameter from `Adapter::create` as this was removed from the wintun c library
- Changed return type of `Session::get_read_wait_event` from `Result<winnt::HANDLE, ()>` to `Result<windows::Win32::HANDLE, wintun::Error>`

Plus internal refactoring and cleanup by @ssrlive: https://github.com/nulldotblack/wintun/pull/7. Thanks!

## [0.2.1] - 2021-12-03

### Fixed
Type in readme

## [0.2.0] - 2021-12-03

Added support for wintun 0.14.

### Breaking Changes

- Wintun driver versions before `0.14` are no longer support due to beraking
changes in the C API
- `Adapter::create` returns a `Result<Adapter, ...>` instead of a `Result<CreateData, ...>`.
This was done because the underlying Wintun function was changed to only return an adapter handle
- `Adapter::create` the pool parameter was removed because it was also removed from the C function
- `Adapter::delete` takes no parameters and returns a `Result<(), ()>`.
The `force_close_sessions` parameter was removed because it was removed from the
C function. Same for the bool inside the Ok(..) variant
- `Adapter::create` and `Adapter::open` return `Arc<Adapter>` instead of `Adapter`
- `get_running_driver_version` now returns a proper Result<Version, ()>. 

### Added

- `reset_logger` function to disable logging after a logger has been set.

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

