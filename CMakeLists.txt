cmake_minimum_required(VERSION 3.22)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

project(kritis3m_asl)


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

# Enable direct access to the WolfSSL API
option(KRITIS3M_ASL_INTERNAL_API "Enable access to internal WolfSSL API" OFF)


if(KRITIS3M_ASL_EXTERNAL_WOLFSSL)

# Search for system-wide installed WolfSSL
find_package(liboqs REQUIRED)
find_package(wolfssl REQUIRED)

else(KRITIS3M_ASL_EXTERNAL_WOLFSSL)

# External repositories we need
include(FetchContent)
Set(FETCHCONTENT_QUIET FALSE)
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


# Write the configuration into a file
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/src/priv_include/asl_config.h.in asl_config.h)


# Define the main library
add_library(asl
        ${CMAKE_CURRENT_SOURCE_DIR}/src/asl.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/asl_logging.c
)

target_include_directories(asl PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}>
        $<INSTALL_INTERFACE:include/kritis3m_asl>
)

target_include_directories(asl PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/priv_include
)

target_link_libraries(asl PRIVATE wolfssl)


# Create combined static library that includes all dependencies
if (NOT BUILD_SHARED_LIBS)

set(LIBNAME "libkritis3m_asl.a")

set(WOLFSSL_TARGET_NAME "wolfssl")
set(LIBOQS_TARGET_NAME "oqs")

if(KRITIS3M_ASL_EXTERNAL_WOLFSSL)
        set(WOLFSSL_TARGET_NAME "wolfssl::wolfssl")
        set(LIBOQS_TARGET_NAME "OQS::oqs")
endif(KRITIS3M_ASL_EXTERNAL_WOLFSSL)

set(create_combined_lib_script
        "create ${LIBNAME}\naddlib $<TARGET_FILE:asl>\naddlib $<TARGET_FILE:${WOLFSSL_TARGET_NAME}>\naddlib $<TARGET_FILE:${LIBOQS_TARGET_NAME}>\nsave\nend\n"
)

file(GENERATE OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/create_combined_lib_script.ar"
        CONTENT ${create_combined_lib_script}
        CONDITION 1
)

add_custom_command(TARGET asl POST_BUILD
        DEPENDS wolfssl oqs
        COMMAND ${CMAKE_AR} -M < create_combined_lib_script.ar
        COMMENT "Creating combined static library ${LIBNAME}"
)

# Install the combined library file
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/${LIBNAME} TYPE LIB)

endif(NOT BUILD_SHARED_LIBS)


# Install files
install(TARGETS asl EXPORT kritis3m_asl-export DESTINATION lib)
install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/ DESTINATION include/kritis3m_asl)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/asl_config.h DESTINATION include/kritis3m_asl)

# Install CMake configuration files
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/cmake/kritis3m_asl-config.cmake DESTINATION lib/cmake/kritis3m_asl)
install(EXPORT kritis3m_asl-export DESTINATION lib/cmake/kritis3m_asl FILE kritis3m_asl-export.cmake)
export(EXPORT kritis3m_asl-export FILE kritis3m_asl-export.cmake)

if(KRITIS3M_ASL_INTERNAL_API AND NOT KRITIS3M_ASL_EXTERNAL_WOLFSSL)
        # Install the internal WolfSSL header files
        install(DIRECTORY ${wolfssl_SOURCE_DIR}/wolfssl/ DESTINATION include/kritis3m_asl/wolfssl)
        install(DIRECTORY ${wolfssl_BINARY_DIR}/wolfssl/ DESTINATION include/kritis3m_asl/wolfssl)
        install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/src/priv_include/wolfssl/ DESTINATION include/kritis3m_asl)
        install(DIRECTORY ${OQS_BINARY_DIR}/../include/ DESTINATION include/kritis3m_asl)
endif()
