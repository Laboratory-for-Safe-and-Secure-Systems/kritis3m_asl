# KRITIS³M ASL Zephyr Port

The kritis3m_asl can be used as a module for the [Zephyr RTOS](https://www.zephyrproject.org/).

## Installation

You have to add the repository to your West workspace using a [West Manifest](https://docs.zephyrproject.org/latest/develop/west/manifest.html#west-manifests)

In your manifest file (`west.yml`), add the following:
```
remotes:
    # <other remotes>
    - name: kritis3m_asl
      url-base: https://github.com/Laboratory-for-Safe-and-Secure-Systems/kritis3m_asl

projects:
    # <other projects>
    - name: kritis3m_asl
      path: modules/crypto/kritis3m_asl
      revision: main
      remote: kritis3m_asl
```

After adding the new information to your manifest file, run `west update` to download and install the library as a Zephyr module. After that, you can use it in your projects.

## Usage

The port provides a variety of configurable options using Kconfig. Once you have the kritis3m_asl module enabled with `CONFIG_KRITIS3M_ASL=y`, you can manually enable or disable specific features.

Currently, the following options are available:
* `CONFIG_KRITIS3M_ASL_PKCS11=y/n`: Enable PKCS#11 support. Default `n`.
* `CONFIG_KRITIS3M_ASL_INTERNAL_API=y/n`: Enable access to WolfSSL internal API.  Default `n`.