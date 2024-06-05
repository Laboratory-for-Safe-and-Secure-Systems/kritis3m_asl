cmake_minimum_required(VERSION 3.22)

project(kritis3m_asl)

# Make sure VSCode and IntelliSense finds its necessary data
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)


option(KRITIS3M_ASL_ENABLE_PKCS11 "Enable PKCS11 support" ON)
option(KRITIS3M_ASL_INTERNAL_API "Enable access to internal WolfSSL API" OFF)


include(FetchContent)
Set(FETCHCONTENT_QUIET FALSE)

# External repositories we need
FetchContent_Declare(liboqs
    GIT_REPOSITORY          https://github.com/open-quantum-safe/liboqs.git
    GIT_TAG                 origin/main
    GIT_PROGRESS            TRUE
    USES_TERMINAL_DOWNLOAD  TRUE
)

FetchContent_Declare(wolfssl
    GIT_REPOSITORY          git@github.com:Laboratory-for-Safe-and-Secure-Systems/wolfssl.git
    GIT_TAG                 origin/development
    GIT_PROGRESS            TRUE
    USES_TERMINAL_DOWNLOAD  TRUE
)


# Liboqs configuration
set(OQS_DIST_BUILD  OFF)
set(OQS_BUILD_ONLY_LIB ON)
set(OQS_USE_OPENSSL OFF)
set(OQS_ENABLE_KEM_BIKE OFF)
set(OQS_ENABLE_KEM_FRODOKEM OFF)
set(OQS_ENABLE_KEM_NTRUPRIME OFF)
set(OQS_ENABLE_KEM_CLASSIC_MCELIECE OFF)
set(OQS_ENABLE_KEM_HQC OFF)
set(OQS_ENABLE_KEM_ML_KEM OFF)
set(OQS_ENABLE_SIG_SPHINCS OFF)
set(OQS_ENABLE_SIG_ML_DSA OFF)

# WolfSSL configuration
set(WOLFSSL_USER_SETTINGS ON)
set(WOLFSSL_EXAMPLES OFF)
set(WOLFSSL_CRYPT_TESTS OFF)
set(BUILD_SHARED_LIBS OFF)
set(WOLFSSL_OQS OFF)
set(WOLFSSL_BUILD_OUT_OF_TREE ON)

# Actually add the external repositories to our project
FetchContent_GetProperties(liboqs)
if(NOT liboqs_POPULATED)
  FetchContent_Populate(liboqs)
  add_subdirectory(${liboqs_SOURCE_DIR} ${liboqs_BINARY_DIR} EXCLUDE_FROM_ALL)
endif()

FetchContent_GetProperties(wolfssl)
if(NOT wolfssl_POPULATED)
  FetchContent_Populate(wolfssl)
  add_subdirectory(${wolfssl_SOURCE_DIR} ${wolfssl_BINARY_DIR} EXCLUDE_FROM_ALL)
endif()

# In order for WolfSSL to find the 'user_settings.h' file, we have to
# provide the directory where it is located.
target_include_directories(wolfssl PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/priv_include/wolfssl>)

# Provide the liboqs headers (generated during build) for WolfSSL
get_target_property(OQS_BINARY_DIR oqs BINARY_DIR)
target_include_directories(wolfssl PUBLIC $<BUILD_INTERFACE:${OQS_BINARY_DIR}/../include>)

# Link liboqs to WolfSSL
target_link_libraries(wolfssl PRIVATE oqs)


# Write the configuration into a file
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/src/priv_include/asl_config.h.in asl_config.h)


# Define the main library
add_library(asl STATIC
        ${CMAKE_CURRENT_SOURCE_DIR}/src/asl.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/asl_logging.c
)

target_include_directories(asl PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_BINARY_DIR}
)

target_include_directories(asl PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/priv_include
)

target_link_libraries(asl PRIVATE wolfssl)


# Add PKCS11 related stuff
if(KRITIS3M_ASL_ENABLE_PKCS11)
        target_sources(asl PRIVATE
                ${CMAKE_CURRENT_SOURCE_DIR}/src/wolfssl_pkcs11_pqc.c
        )
endif()


# Create combined static library that includes all dependencies
set(LIBNAME "libkritis3m_asl.a")

set(create_combined_lib_script
        "create ${LIBNAME}\naddlib $<TARGET_FILE:asl>\naddlib $<TARGET_FILE:wolfssl>\naddlib $<TARGET_FILE:oqs>\nsave\nend\n"
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

# Install the library files
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/${LIBNAME} TYPE LIB)

# Install header files
install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/ DESTINATION include/kritis3m_asl)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/asl_config.h DESTINATION include/kritis3m_asl)

if(KRITIS3M_ASL_INTERNAL_API)
        # Install the internal WolfSSL header files
        install(DIRECTORY ${wolfssl_SOURCE_DIR}/wolfssl/ DESTINATION include/kritis3m_asl/wolfssl)
        install(DIRECTORY ${wolfssl_BINARY_DIR}/wolfssl/ DESTINATION include/kritis3m_asl/wolfssl)
        install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/src/priv_include/wolfssl/ DESTINATION include/kritis3m_asl)
        install(DIRECTORY ${OQS_BINARY_DIR}/../include/ DESTINATION include/kritis3m_asl)
endif()
