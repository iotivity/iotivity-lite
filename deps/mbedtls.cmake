# Do not build anything except for the library
option(ENABLE_PROGRAMS "Build mbed TLS programs." OFF)
option(ENABLE_TESTING "Build mbed TLS tests." OFF)

# Build static library only
set(USE_STATIC_MBEDTLS_LIBRARY ON CACHE BOOL "Build mbed TLS static library." FORCE)
set(USE_SHARED_MBEDTLS_LIBRARY OFF CACHE BOOL "Build mbed TLS shared library." FORCE)

# Patch mbedtls
set(OC_REAPPLY_MBEDTLS_PATCHES ON CACHE BOOL "")
if(OC_REAPPLY_MBEDTLS_PATCHES)
    include(mbedtls-patch.cmake)
    set(OC_REAPPLY_MBEDTLS_PATCHES OFF CACHE BOOL
        "By default, mbedTLS patches are applied upon the first CMake Configure. Set this to ON to reapply the patches on the next configure."
         FORCE
    )
endif()

# If an mbedtls platform layer is defined, add it to the mbedtls list of libs
if(TARGET mbedtls-plat)
    set(libs ${libs} mbedtls-plat)
endif()

add_subdirectory(${PROJECT_SOURCE_DIR}/deps/mbedtls)

# do not treat warnings as errors on Windows
# block should be defined after the target library
if(MSVC)
    target_compile_options(mbedtls PRIVATE /W1 /WX-)
    target_compile_options(mbedx509 PRIVATE /W1 /WX-)
    target_compile_options(mbedcrypto PRIVATE /W1 /WX-)
endif()

if(OC_DYNAMIC_ALLOCATION_ENABLED)
    target_compile_definitions(mbedcrypto PUBLIC OC_DYNAMIC_ALLOCATION)
endif()

if(OC_SECURITY_ENABLED)
    target_compile_definitions(mbedcrypto PUBLIC OC_SECURITY)
endif()

if(OC_PKI_ENABLED)
    target_compile_definitions(mbedcrypto PUBLIC OC_PKI)
endif()

if(OC_DEBUG_ENABLED)
    target_compile_definitions(mbedcrypto PUBLIC OC_DEBUG)
endif()

target_include_directories(mbedcrypto PUBLIC
    ${PROJECT_SOURCE_DIR}
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/deps/mbedtls/include
)

if(UNIX)
    target_include_directories(mbedcrypto PUBLIC ${PROJECT_SOURCE_DIR}/port/linux)
elseif(WIN32)
    target_include_directories(mbedcrypto PUBLIC ${PROJECT_SOURCE_DIR}/port/windows)
endif()

# If an mbedtls platform layer is defined, add it to the mbedtls list of libs
if(TARGET mbedcrypto-plat)
    target_link_libraries(mbedcrypto mbedcrypto-plat)
endif()
