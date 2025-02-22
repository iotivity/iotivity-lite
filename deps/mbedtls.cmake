# Patch mbedtls
set(OC_REAPPLY_MBEDTLS_PATCHES ON CACHE BOOL "")

if(OC_REAPPLY_MBEDTLS_PATCHES)
    include(${PROJECT_SOURCE_DIR}/deps/mbedtls-patch.cmake)
    set(OC_REAPPLY_MBEDTLS_PATCHES OFF CACHE BOOL
        "By default, mbedTLS patches are applied upon the first CMake Configure. Set this to ON to reapply the patches on the next configure."
        FORCE
    )
endif()

# use command-line parameters to enable mbedtls unit tests / helper programs
option(ENABLE_PROGRAMS "Build mbed TLS programs." OFF)
option(ENABLE_TESTING "Build mbed TLS tests." OFF)
# generate export sets for mbedtls targets
option(DISABLE_PACKAGE_CONFIG_AND_INSTALL ON)

if(OC_INSTALL_MBEDTLS)
    add_subdirectory(${PROJECT_SOURCE_DIR}/deps/mbedtls)
else()
    add_subdirectory(${PROJECT_SOURCE_DIR}/deps/mbedtls EXCLUDE_FROM_ALL)
endif()

set(COMPILABLE_TYPES STATIC_LIBRARY MODULE_LIBRARY SHARED_LIBRARY OBJECT_LIBRARY EXECUTABLE)

function(get_all_targets_in_directory dir out_var)
    get_property(all_targets DIRECTORY ${dir} PROPERTY BUILDSYSTEM_TARGETS)
    get_property(subdirs DIRECTORY ${dir} PROPERTY SUBDIRECTORIES)

    foreach(subdir ${subdirs})
        get_all_targets_in_directory(${subdir} subdir_targets)
        list(APPEND all_targets ${subdir_targets})
    endforeach()

    set(targets)

    foreach(target ${all_targets})
        get_target_property(target_type ${target} TYPE)

        if(NOT(${target_type} IN_LIST COMPILABLE_TYPES))
            continue()
        endif()

        list(APPEND targets ${target})
    endforeach()

    set(${out_var} ${targets} PARENT_SCOPE)
endfunction()

get_all_targets_in_directory(${PROJECT_SOURCE_DIR}/deps/mbedtls/library mbedtls_library)
set(mbedtls_targets ${mbedtls_library})

if(ENABLE_TESTING OR ENABLE_PROGRAMS)
    # * abort.c -  MBEDTLS_PLATFORM_STD_EXIT is defined as oc_exit and mbedtls utilities need to include implementation of oc_exit
    set(MBEDTLS_SUPPORT_SRC ${PORT_INCLUDE_DIR}/abort.c)

    add_library(mbedtls-support
        OBJECT ${MBEDTLS_SUPPORT_SRC}
    )
    target_compile_definitions(mbedtls-support
        PRIVATE ${PRIVATE_COMPILE_DEFINITIONS}
        PUBLIC ${PUBLIC_COMPILE_DEFINITIONS}
    )
    target_include_directories(mbedtls-support PRIVATE
        ${PROJECT_SOURCE_DIR}
        ${PROJECT_SOURCE_DIR}/include
        ${PORT_INCLUDE_DIR}
    )
endif()

if(CMAKE_SYSTEM_PROCESSOR MATCHES "arm" OR CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64")
if(NOT BUILD_MBEDTLS_FORCE_3_5_0 AND OC_COMPILER_IS_GCC)
    # there is a false positive in ctr_drbg.c when built with default arm64 gcc
    #
    # inlined from 'ctr_drbg_update_internal' at /iotivity-lite/deps/mbedtls/library/ctr_drbg.c:372:5:
    # /iotivity-lite/deps/mbedtls/library/common.h:235:17: error: array subscript 48 is outside array bounds of 'unsigned char[48]' [-Werror=array-bounds=]
    #         r[i] = a[i] ^ b[i];
    #
    list(APPEND MBEDTLS_COMPILE_OPTIONS -Wno-error=array-bounds)
endif()
endif()

foreach(target ${mbedtls_targets})
    target_compile_definitions(${target} PRIVATE ${MBEDTLS_COMPILE_DEFINITIONS})

    if(OC_COMPILER_IS_GCC OR OC_COMPILER_IS_CLANG)
        target_compile_options(${target} PRIVATE -Wno-error=unused)
    endif()

    target_compile_options(${target} PRIVATE ${MBEDTLS_COMPILE_OPTIONS})

    # do not treat warnings as errors on Windows
    if(MSVC)
        target_compile_options(${target} PRIVATE /W1 /WX-)
    endif()

    target_include_directories(${target} PRIVATE
        ${PROJECT_SOURCE_DIR}
        ${PROJECT_SOURCE_DIR}/include
        ${PORT_INCLUDE_DIR}
    )

    if(TARGET mbedtls-support)
        target_sources(${target} PRIVATE $<TARGET_OBJECTS:mbedtls-support>)
    endif()
endforeach()
