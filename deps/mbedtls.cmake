# Patch mbedtls
set(OC_REAPPLY_MBEDTLS_PATCHES ON CACHE BOOL "")
if(OC_REAPPLY_MBEDTLS_PATCHES)
    include(${PROJECT_SOURCE_DIR}/deps/mbedtls-patch.cmake)
    set(OC_REAPPLY_MBEDTLS_PATCHES OFF CACHE BOOL
        "By default, mbedTLS patches are applied upon the first CMake Configure. Set this to ON to reapply the patches on the next configure."
         FORCE
    )
endif()

file(GLOB MBEDTLS_SRC
    ${PROJECT_SOURCE_DIR}/deps/mbedtls/library/*.c
)
list(REMOVE_ITEM MBEDTLS_SRC
    ${PROJECT_SOURCE_DIR}/deps/mbedtls/library/certs.c
    ${PROJECT_SOURCE_DIR}/deps/mbedtls/library/memory_buffer_alloc.c
    ${PROJECT_SOURCE_DIR}/deps/mbedtls/library/x509_crl.c
)
add_library(mbedtls OBJECT ${MBEDTLS_SRC})
target_include_directories(mbedtls PRIVATE
    ${PROJECT_SOURCE_DIR}
    ${PROJECT_SOURCE_DIR}/include
    ${PORT_INCLUDE_DIR}
    ${PROJECT_SOURCE_DIR}/deps/mbedtls/include
)
target_compile_definitions(mbedtls PUBLIC ${PUBLIC_COMPILE_DEFINITIONS} PRIVATE ${PRIVATE_COMPILE_DEFINITIONS} __OC_RANDOM)
target_compile_options(mbedtls PRIVATE ${PRIVATE_COMPILE_OPTIONS})
# do not treat warnings as errors on Windows
if(MSVC)
    target_compile_options(mbedtls PRIVATE /W1 /WX-)
endif()
add_dependencies(mbedtls ${TARGET_DEPENDENCIES})
