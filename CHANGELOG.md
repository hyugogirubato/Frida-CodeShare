# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.0] - 2023-09-22

## Added

- **Native**: Possibility of adding addresses manually to attached by library.
- **Native**: Color activation choice option (support non-colored shell).
- **Native**: Added staggered boot option.
- **Native**: Multiple extension support (`.so`, `.dll`, `.exe`, etc..)

### Changed

- **Native**: Script adapted to support Windows and Linux in addition to Android.
- **Native**: Code rewriting and optimization.
- **Native**: Full regex support for some options.
- **Native**: Improved debug information.
- **Native**: Readme update.

## Fixed

- **Native**: Base64 display correction (Hex display if Java not available).

## [1.1.5] - 2023-09-18

### Added

- **Native**: Support for the `Integer` type for return codes.

### Fixed

- **Native**: Problems displaying recursive mode (argument number colliding with other calls).
- **Native**: Fixed automatic detection of the number of arguments per function (experimental).

### Changed

- **Native**: Removed detection of `UUID` form in `hex` format.
- **Crypto**: Removed detection of `UUID` form in `hex` format.

## [1.1.4] - 2023-08-15

### Added

- **Native**: Added debug information option for library/module/variable

## [1.1.3] - 2023-08-06

### Added

- **Native**: Added simple regex support for short function names.

## [1.1.2] - 2023-08-04

### Added

- **Native**: Added recursive display of function arguments.

## [1.1.1] - 2023-07-29

### Fixed

- **Native**: Added multi-thread support for base64 conversion.

## [1.1.0] - 2023-06-27

### Added

- **Pinning**: Initial Release.

## [1.0.3] - 2023-06-20

### Added

- **Crypto**: Hex output when the size matches a classic standard.
- **Native**: `UUID` support for hex format.

### Fixed

- **Crypto**: Fixed display of `useKeyGen.build`.

### Changed

- **Crypto**: Better error support when coding with null values.

## [1.0.2] - 2023-06-16

### Fixed

- **Crypto**: Fixed crypto and decoding operations.

## [1.0.1] - 2023-06-13

### Added

- **Native**: Added detection of a pointer as an argument.

## [1.0.0] - 2023-06-09

### Added

- Initial Release.

[1.2.0]: https://github.com/hyugogirubato/Frida-CodeShare/releases/tag/v1.2.0
[1.1.5]: https://github.com/hyugogirubato/Frida-CodeShare/releases/tag/v1.1.5
[1.1.4]: https://github.com/hyugogirubato/Frida-CodeShare/releases/tag/v1.1.4
[1.1.3]: https://github.com/hyugogirubato/Frida-CodeShare/releases/tag/v1.1.3
[1.1.2]: https://github.com/hyugogirubato/Frida-CodeShare/releases/tag/v1.1.2
[1.1.1]: https://github.com/hyugogirubato/Frida-CodeShare/releases/tag/v1.1.1
[1.1.0]: https://github.com/hyugogirubato/Frida-CodeShare/releases/tag/v1.1.0
[1.0.3]: https://github.com/hyugogirubato/Frida-CodeShare/releases/tag/v1.0.3
[1.0.2]: https://github.com/hyugogirubato/Frida-CodeShare/releases/tag/v1.0.2
[1.0.1]: https://github.com/hyugogirubato/Frida-CodeShare/releases/tag/v1.0.1
[1.0.0]: https://github.com/hyugogirubato/Frida-CodeShare/releases/tag/v1.0.0
