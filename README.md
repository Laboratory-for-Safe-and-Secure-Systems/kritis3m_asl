# KRITIS³M Agile Security Library

This repository contains the code for the Agile Security Library (ASL), a wrapper library to simplify integration of TLS into applications via a generic and flexble interface to improve Crypto-Agility.

## Building

The project uses CMake to be built.

```bash
mkdir build && cd build
cmake [options] ..
make
sudo make install
```

You can also use Ninja as a build tool by specifying `-GNinja` within the CMake invocation.

The library has a few dependencies listed below. By default, those are cloned using the CMake FetchContent functionality. However, you can also specify their source directory via CMake variables (given below for each dependency) to prevent additional downloads.

* [kritis3m_wolfssl](https://github.com/Laboratory-for-Safe-and-Secure-Systems/kritis3m_wolfssl): Wrapper repository for the WolfSSL fork and the liboqs library with the specific configuration of both libraries (`-DFETCHCONTENT_SOURCE_DIR_KRITIS3M_WOLFSSL=/path/to/kritis3m_wolfssl`).
* [wolfssl](https://github.com/Laboratory-for-Safe-and-Secure-Systems/wolfssl): KRITIS³M fork of WolfSSL with downstream changes (`-DFETCHCONTENT_SOURCE_DIR_WOLFSSL=/path/to/wolfssl`).
* [liboqs](https://github.com/open-quantum-safe/liboqs): Library for support of the PQC algorithm FALCON (`-DFETCHCONTENT_SOURCE_DIR_LIBOQS=/path/to/liboqs`).

The built library and its header are installed in the default CMake installation paths. Another install path may be specified via the default CMake `CMAKE_INSTALL_PREFIX` variable.

### CLI build options

The following additional CMake options are available to customize the compilation of the library:
* `BUILD_SHARED_LIBS`: Select between shared libraries (.so/.dll) and static libraries (.a/.lib). Default: `ON`.
* `KRITIS3M_ASL_STANDALONE`: When this option is enabled, the kritis3m_wolfssl dependency will be built as standalone library to be installed system-wide. When disabled, the library will be built as a library only to be linked against a wrapping application. Default: `ON`.
* `KRITIS3M_ASL_EXTERNAL_WOLFSSL`: Use an externally installed WolfSSL library via `find_package()`. If disabled, WolfSSL will be built. Default: `OFF`.
* `KRITIS3M_ASL_ENABLE_PKCS11`: Enable PKCS11 support. Default: `ON`.
* `KRITIS3M_ASL_ENABLE_FALCON`: Enable support for the PQC signature algorithm FALCON (FN-DSA) via the additional library liboqs. When disabled, the library will not be built. Default: `ON`.
* `KRITIS3M_ASL_INTERNAL_API`: Enable direct access to the WolfSSL API. Default: `OFF`.
* `KRITIS3M_ASL_COMBINED_STATIC_LIB`: Create a combined static library that includes all dependencies. Default: `OFF`.

### Helper files

Furthermore, helper files for easier handling of the library are also generated and installed during system-wide installation:
*  CMake export and config files. This enables CMake to find the library using `find_package()` functionality
* pkg-config files for the equally named tool

When the CMake option `KRITIS3M_ASL_COMBINED_STATIC_LIB` is enabled, a static library is created additionally (`libkritis3m_asl_full.a`). This contains all dependencies for easier integration into custom projects without proper dynamic loader support.

### Zephyr support

The library can also be used as a Zephyr module. After adding it to the Zephyr workspace via the manifest, you can enable and customize the build using Kconfig.

Please refer to the [Zephyr directory](zephyr/README.md) for more information.

## Usage

The idea behind the ASL is to provide a minimal interface for applications to establish and use TLS connections.