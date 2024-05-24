# SPDX-License-Identifier: MIT

# Only add module if enabled in Kconfig
if(CONFIG_KRITIS3M_ASL)

        zephyr_interface_library_named(kritis3m_asl)

        zephyr_include_directories(
                ${ZEPHYR_CURRENT_MODULE_DIR}/include
        )

        zephyr_library()
        zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/src/asl.c)

        # Add PKCS11 related stuff
        if(CONFIG_KRITIS3M_ASL_PKCS11)
                zephyr_library_sources(
                        ${ZEPHYR_CURRENT_MODULE_DIR}/src/wolfssl_pkcs11_pqc.c
                )
        endif()

        zephyr_library_link_libraries(kritis3m_asl)

        # ToDo: these should not be accessable from the outside
        target_include_directories(kritis3m_asl INTERFACE
                ${ZEPHYR_CURRENT_MODULE_DIR}/src/priv_include
        )

        target_link_libraries(kritis3m_asl INTERFACE wolfSSL)

        target_link_libraries(kritis3m_asl INTERFACE zephyr_interface)
endif()