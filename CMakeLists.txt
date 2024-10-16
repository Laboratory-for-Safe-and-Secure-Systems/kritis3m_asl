cmake_minimum_required(VERSION 3.22)

project(kritis3m_asl)

include(GNUInstallDirs)
include(FetchContent)
set(FETCHCONTENT_QUIET FALSE)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Necessary to allow FetchContent_Populate
if(POLICY CMP0169)
        cmake_policy(SET CMP0169 OLD)
endif()


# Options

# Select between shared or static libraries
option(BUILD_SHARED_LIBS "Build shared libraries (.so) instead of static ones (.a)" ON)

# When this option is enabled, the KRITIS3M_wolfssl dependency will be built as standalone
# library to be installed system-wide. When disabled, the library will be built as a library
# only to be linked against a wrapping application.
option(KRITIS3M_ASL_STANDALONE "Use standalone WolfSSL" ON)

# Use an externally installed WolfSSL library. If disabled, WolfSSL will be built.
option(KRITIS3M_ASL_EXTERNAL_WOLFSSL "Use external WolfSSL library" OFF)

# Enable PKCS11 support in WolfSSL
option(KRITIS3M_ASL_ENABLE_PKCS11 "Enable PKCS11 support" ON)

# Enable PKCS11 crypto
option(KRITIS3M_ASL_PKCS11_CRYPTO "Use a PKCS11 library for crypto operations" ON)

# Enable direct access to the WolfSSL API
option(KRITIS3M_ASL_INTERNAL_API "Enable access to internal WolfSSL API" OFF)

# Create a combined static library that includes all dependencies
option(KRITIS3M_ASL_COMBINED_STATIC_LIB "Create a combined static library" OFF)


if(KRITIS3M_ASL_PKCS11_CRYPTO)
        # WolfPKCS11 needs shared libraries
        set(BUILD_SHARED_LIBS ON)
endif()


# Pull in WolfSSL as dependency (either as an external library or as a subproject)
if(KRITIS3M_ASL_EXTERNAL_WOLFSSL)
        # Search for system-wide installed WolfSSL
        find_package(liboqs REQUIRED)
        find_package(wolfssl REQUIRED)

else(KRITIS3M_ASL_EXTERNAL_WOLFSSL)
        # Pull in kritis3m_wolfssl as a dependency
        FetchContent_Declare(kritis3m_wolfssl
                GIT_REPOSITORY          git@github.com:Laboratory-for-Safe-and-Secure-Systems/kritis3m_wolfssl.git
                GIT_TAG                 origin/main
                GIT_PROGRESS            TRUE
                USES_TERMINAL_DOWNLOAD  TRUE
        )

        # Configuration
        set(KRITIS3M_WOLFSSL_STANDALONE ${KRITIS3M_ASL_STANDALONE})

        # Actually add the external repositories to our project
        FetchContent_GetProperties(kritis3m_wolfssl)
        if(NOT kritis3m_wolfssl_POPULATED)
                FetchContent_Populate(kritis3m_wolfssl)
                if(KRITIS3M_ASL_STANDALONE)
                        add_subdirectory(${kritis3m_wolfssl_SOURCE_DIR} ${kritis3m_wolfssl_BINARY_DIR})
                else()
                        add_subdirectory(${kritis3m_wolfssl_SOURCE_DIR} ${kritis3m_wolfssl_BINARY_DIR} EXCLUDE_FROM_ALL)
                endif()
        endif()
endif(KRITIS3M_ASL_EXTERNAL_WOLFSSL)


# Pull wolfPKCS11 as dependency when required
if(KRITIS3M_ASL_PKCS11_CRYPTO)
        FetchContent_Declare(wolfpkcs11
                GIT_REPOSITORY          git@github.com:Laboratory-for-Safe-and-Secure-Systems/wolfPKCS11.git
                GIT_TAG                 origin/development
                GIT_PROGRESS            TRUE
                USES_TERMINAL_DOWNLOAD  TRUE
        )

        # Actually add the external repositories to our project
        FetchContent_GetProperties(wolfpkcs11)
        if(NOT wolfpkcs11_POPULATED)
                FetchContent_Populate(wolfpkcs11)
                if(KRITIS3M_ASL_STANDALONE)
                        add_subdirectory(${wolfpkcs11_SOURCE_DIR} ${wolfpkcs11_BINARY_DIR})
                else()
                        add_subdirectory(${wolfpkcs11_SOURCE_DIR} ${wolfpkcs11_BINARY_DIR} EXCLUDE_FROM_ALL)
                endif()
        endif()
endif()


# Write the configuration into a file
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/src/priv_include/asl_config.h.in asl_config.h)


# Define the main library
add_library(kritis3m_asl
        ${CMAKE_CURRENT_SOURCE_DIR}/src/asl.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/asl_logging.c
)

# Public headers
target_include_directories(kritis3m_asl PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}/kritis3m_asl>
)

# Private headers
target_include_directories(kritis3m_asl PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/priv_include
)

# Link against WolfSSL
target_link_libraries(kritis3m_asl PRIVATE wolfssl)

# Add a preprocessor definition to indicate that we are building the library
# This is required to distinguish between building the library and using it
# in an application within the header files.
target_compile_definitions(kritis3m_asl PRIVATE "BUILDING_KRITIS3M_ASL")
if(BUILD_SHARED_LIBS)
    target_compile_definitions(kritis3m_asl PUBLIC "BUILDING_KRITIS3M_ASL_SHARED")
endif()


if(KRITIS3M_ASL_PKCS11_CRYPTO)
        target_link_libraries(wolfpkcs11 PRIVATE wolfssl)
        add_dependencies(kritis3m_asl wolfpkcs11)
endif()


# Install library and header files
install(TARGETS kritis3m_asl
        EXPORT kritis3m_asl-export
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/kritis3m_asl
)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/asl_config.h
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/kritis3m_asl
)

# Install CMake configuration files so other CMake projects can find this library
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/cmake/kritis3m_asl-config.cmake
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/kritis3m_asl
)
install(EXPORT kritis3m_asl-export
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/kritis3m_asl
        FILE kritis3m_asl-export.cmake
)
export(EXPORT kritis3m_asl-export
       FILE kritis3m_asl-export.cmake
)

# Generate pkg-config file
configure_file(
        ${CMAKE_CURRENT_SOURCE_DIR}/cmake/kritis3m_asl.pc.in
        ${CMAKE_CURRENT_BINARY_DIR}/kritis3m_asl.pc
        @ONLY
)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/kritis3m_asl.pc
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig
)


# When internal API access is enabled, install the WolfSSL headers
if(KRITIS3M_ASL_INTERNAL_API AND NOT KRITIS3M_ASL_EXTERNAL_WOLFSSL)
        # Install the internal WolfSSL header files
        install(DIRECTORY ${wolfssl_SOURCE_DIR}/wolfssl/
                DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/kritis3m_asl/wolfssl
        )
        install(DIRECTORY ${wolfssl_BINARY_DIR}/wolfssl/
                DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/kritis3m_asl/wolfssl
        )
        install(FILES ${kritis3m_wolfssl_SOURCE_DIR}/user_settings.h
                DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/kritis3m_asl
        )
        install(DIRECTORY ${liboqs_BINARY_DIR}/include/
                DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/kritis3m_asl
        )
endif()


# Create combined static library that includes all dependencies
if (NOT BUILD_SHARED_LIBS AND KRITIS3M_ASL_COMBINED_STATIC_LIB)
        set(LIBNAME "libkritis3m_asl_full.a")
        set(WOLFSSL_TARGET_NAME "wolfssl")
        set(LIBOQS_TARGET_NAME "oqs")

        # When using external WolfSSL, we need to use the imported targets
        # which contain a CMake namespace prefix
        if(KRITIS3M_ASL_EXTERNAL_WOLFSSL)
                set(WOLFSSL_TARGET_NAME "wolfssl::wolfssl")
                set(LIBOQS_TARGET_NAME "OQS::oqs")
        endif(KRITIS3M_ASL_EXTERNAL_WOLFSSL)

        string(CONCAT create_combined_lib_script
                "create ${LIBNAME}\n"
                "addlib $<TARGET_FILE:kritis3m_asl>\n"
                "addlib $<TARGET_FILE:${WOLFSSL_TARGET_NAME}>\n"
                "addlib $<TARGET_FILE:${LIBOQS_TARGET_NAME}>\n"
                "save\nend\n"
        )

        file(GENERATE OUTPUT
                "${CMAKE_CURRENT_BINARY_DIR}/create_combined_lib_script.ar"
                CONTENT ${create_combined_lib_script}
                CONDITION 1
        )

        add_custom_command(TARGET kritis3m_asl POST_BUILD
                COMMAND ${CMAKE_AR} -M < create_combined_lib_script.ar
                COMMENT "Creating combined static library ${LIBNAME}"
        )

        # Install the combined library file
        install(FILES ${CMAKE_CURRENT_BINARY_DIR}/${LIBNAME} TYPE LIB)
endif()
