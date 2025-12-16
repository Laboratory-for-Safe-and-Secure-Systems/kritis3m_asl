# SPDX-License-Identifier: MIT

# Only add module if enabled in Kconfig
if(CONFIG_KRITIS3M_ASL)

        zephyr_interface_library_named(kritis3m_asl)

        zephyr_include_directories(
                ${ZEPHYR_CURRENT_MODULE_DIR}/include
                ${CMAKE_CURRENT_BINARY_DIR}
        )

        zephyr_library()
        zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/src/asl_general.c)
        zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/src/asl_endpoint.c)
        zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/src/asl_session.c)
        zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/src/asl_logging.c)
        zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/src/asl_psk.c)
        zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/src/asl_pkcs11.c)

        # Add PKCS11 related stuff
        if(CONFIG_KRITIS3M_ASL_PKCS11)
                zephyr_library_sources(
                        ${ZEPHYR_CURRENT_MODULE_DIR}/zephyr/secure_element_i2c.c
                )
                set(KRITIS3M_ASL_ENABLE_PKCS11 ON)
        endif()

        if(CONFIG_KRITIS3M_ASL_INTERNAL_API)
                set(KRITIS3M_ASL_ENABLE_INTERNAL_API ON)
        endif()

        if (CONFIG_KRITIS3M_ASL_HEAP_TRACKING)
                set(KRITIS3M_ASL_HEAP_TRACKING ON)
        endif()

        if (CONFIG_KRITIS3M_ASL_CONSTANT_PRNG)
                set(KRITIS3M_ASL_CONSTANT_PRNG ON)
        endif()

        if (CONFIG_KRITIS3M_ASL_LOG_INIT_DURATION)
                set(KRITIS3M_ASL_LOG_INIT_DURATION ON)
        endif()

        zephyr_library_link_libraries(kritis3m_asl)

        # ToDo: these should not be accessable from the outside
        target_include_directories(kritis3m_asl INTERFACE
                ${ZEPHYR_CURRENT_MODULE_DIR}/src/priv_include
        )

        target_link_libraries(kritis3m_asl INTERFACE wolfSSL)

        target_link_libraries(kritis3m_asl INTERFACE zephyr_interface)

        # Write the configuration into a file
        configure_file(${ZEPHYR_CURRENT_MODULE_DIR}/src/priv_include/asl_config.h.in asl_config.h)

endif()