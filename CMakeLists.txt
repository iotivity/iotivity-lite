cmake_minimum_required (VERSION 3.10)
project(iotivity-lite VERSION 2.2.5)

include(GNUInstallDirs) # Installation directories for `install` command and pkgconfig file

######## Build configuration options ########
set(OC_DYNAMIC_ALLOCATION_ENABLED ON CACHE BOOL "Enable dynamic memory allocation within the OCF stack and MBedtls.")
set(OC_SECURITY_ENABLED ON CACHE BOOL "Enable security.")
set(OC_PKI_ENABLED ON CACHE BOOL "Enable PKI security.")
set(OC_CLOUD_ENABLED OFF CACHE BOOL "Enable cloud communications.")
set(OC_DEBUG_ENABLED OFF CACHE BOOL "Enable debug messages.")
set(OC_IDD_API_ENABLED ON CACHE BOOL "Enable the Introspection Device Data API.")
set(OC_TCP_ENABLED ON CACHE BOOL "Enable OCF communications over TCP. Necessary for Cloud communications.")
set(OC_DISCOVERY_RESOURCE_OBSERVABLE_ENABLED OFF CACHE BOOL "Enable observation over oic/res resource.")
set(OC_REPRESENTATION_REALLOC_ENCODING_ENABLED OFF CACHE BOOL "Enable realloc during encoding the representation.")
set(OC_COLLECTIONS_IF_CREATE_ENABLED OFF CACHE BOOL "Enable RT factory for collections.")
set(OC_MNT_ENABLED OFF CACHE BOOL "Enable maintenance resource.")
set(OC_SOFTWARE_UPDATE_ENABLED OFF CACHE BOOL "Enable software update resource.")
set(OC_WKCORE_ENABLED OFF CACHE BOOL "Enable well-known core resource.")
set(OC_OSCORE_ENABLED OFF CACHE BOOL "Enable oscore support.")
set(OC_IPV4_ENABLED OFF CACHE BOOL "Enable IPv4 support.")
set(OC_DNS_LOOKUP_IPV6_ENABLED OFF CACHE BOOL "Enable IPv6 DNS lookup.")

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

######## Define compiler flags ########
set(PRIVATE_COMPILE_DEFINITIONS "")
set(PUBLIC_COMPILE_DEFINITIONS "")
if(OC_DYNAMIC_ALLOCATION_ENABLED)
    list(APPEND PUBLIC_COMPILE_DEFINITIONS "OC_DYNAMIC_ALLOCATION")
endif()

if(OC_SECURITY_ENABLED)
    list(APPEND PUBLIC_COMPILE_DEFINITIONS "OC_SECURITY")
endif()

if(OC_PKI_ENABLED)
    list(APPEND PUBLIC_COMPILE_DEFINITIONS "OC_PKI")
endif()

if(OC_DEBUG_ENABLED)
    list(APPEND PRIVATE_COMPILE_DEFINITIONS "OC_DEBUG")
endif()

if(OC_CLOUD_ENABLED)
    list(APPEND PUBLIC_COMPILE_DEFINITIONS "OC_CLOUD")
    set(OC_TCP_ENABLED ON)
    set(OC_IPV4_ENABLED ON)
endif()

if(OC_IDD_API_ENABLED)
    list(APPEND PUBLIC_COMPILE_DEFINITIONS "OC_IDD_API")
endif()

if(OC_TCP_ENABLED)
    list(APPEND PUBLIC_COMPILE_DEFINITIONS "OC_TCP")
endif()

if(OC_DISCOVERY_RESOURCE_OBSERVABLE_ENABLED)
    list(APPEND PRIVATE_COMPILE_DEFINITIONS "OC_DISCOVERY_RESOURCE_OBSERVABLE")
endif()

if(OC_REPRESENTATION_REALLOC_ENCODING_ENABLED)
    list(APPEND PRIVATE_COMPILE_DEFINITIONS "OC_REP_ENCODING_REALLOC")
endif()

if(OC_COLLECTIONS_IF_CREATE_ENABLED)
    list(APPEND PUBLIC_COMPILE_DEFINITIONS "OC_COLLECTIONS_IF_CREATE")
endif()

if(OC_MNT_ENABLED)
    list(APPEND PUBLIC_COMPILE_DEFINITIONS "OC_MNT")
endif()

if(OC_SOFTWARE_UPDATE_ENABLED)
    list(APPEND PUBLIC_COMPILE_DEFINITIONS "OC_SOFTWARE_UPDATE")
endif()

if(OC_WKCORE_ENABLED)
    list(APPEND PUBLIC_COMPILE_DEFINITIONS "OC_WKCORE")
endif()

if(OC_OSCORE_ENABLED)
    list(APPEND PUBLIC_COMPILE_DEFINITIONS "OC_OSCORE")
endif()

if(OC_IPV4_ENABLED)
    list(APPEND PUBLIC_COMPILE_DEFINITIONS "OC_IPV4")
endif()

if(OC_DNS_LOOKUP_IPV6_ENABLED)
    list(APPEND PRIVATE_COMPILE_DEFINITIONS "OC_DNS_LOOKUP_IPV6")
endif()

######## Gather source files ########
file(GLOB COMMON_SRC
    ${PROJECT_SOURCE_DIR}/api/c-timestamp/timestamp_format.c
    ${PROJECT_SOURCE_DIR}/api/c-timestamp/timestamp_valid.c
    ${PROJECT_SOURCE_DIR}/api/c-timestamp/timestamp_parse.c
    ${PROJECT_SOURCE_DIR}/util/*.c
)

if(OC_PKI_ENABLED)
    list(APPEND COMMON_SRC
        ${PROJECT_SOURCE_DIR}/api/c-timestamp/timestamp_tm.c
    )
endif()

file(GLOB SERVER_SRC
    ${PROJECT_SOURCE_DIR}/messaging/coap/*.c
    ${PROJECT_SOURCE_DIR}/api/*.c
)

set(CLIENT_SRC ${SERVER_SRC})

# Detect the platform and pick the right port
if(UNIX)
    file(GLOB PORT_SRC port/linux/*.c)
    set(PORT_INCLUDE_DIR ${PROJECT_SOURCE_DIR}/port/linux)
elseif(WIN32)
    file(GLOB PORT_SRC port/windows/*.c)
    set(PORT_INCLUDE_DIR ${PROJECT_SOURCE_DIR}/port/windows)
else()
    message(ERROR "Can build only on Linux and Windows!")
endif()
list(APPEND SERVER_SRC ${PORT_SRC})
list(APPEND CLIENT_SRC ${PORT_SRC})

if(OC_SECURITY_ENABLED)
    file(GLOB SECURITY_SRC
        ${PROJECT_SOURCE_DIR}/security/oc_*.c
    )
    list(REMOVE_ITEM SECURITY_SRC
        ${PROJECT_SOURCE_DIR}/security/oc_obt*.c
    )
    list(APPEND SERVER_SRC ${SECURITY_SRC})
    list(APPEND CLIENT_SRC ${SECURITY_SRC})
    if(OC_DYNAMIC_ALLOCATION_ENABLED)
        file(GLOB OBT_SRC
            ${PROJECT_SOURCE_DIR}/security/oc_obt*.c
            )
        list(APPEND CLIENT_SRC ${OBT_SRC})
    endif()
endif()

if(OC_CLOUD_ENABLED)
    file(GLOB CLOUD_SRC api/cloud/*.c)
    set(CLOUD_INCLUDE_DIR ${PROJECT_SOURCE_DIR}/api/cloud)
endif()

######## Define link dependencies ########
set(PRIVATE_LINK_LIBS "")

include(CheckLibraryExists)
check_library_exists(m ceil "" HAVE_LIB_M)
if(HAVE_LIB_M)
    list(APPEND PRIVATE_LINK_LIBS m)
endif(HAVE_LIB_M)

if(MSVC)
    list(APPEND PRIVATE_LINK_LIBS iphlpapi.lib psapi.lib ws2_32.lib)
elseif(WIN32)
    list(APPEND PRIVATE_LINK_LIBS iphlpapi psapi wsock32 ws2_32)
else()
    find_package(Threads REQUIRED)
    list(APPEND PRIVATE_LINK_LIBS Threads::Threads)
endif()

######## Object libraries ########
include(deps/tinycbor.cmake)

if(OC_SECURITY_ENABLED)
    include(deps/mbedtls.cmake)
    get_target_property(MBEDTLS_INCLUDE_DIR mbedtls INCLUDE_DIRECTORIES)
endif()

add_library(common-obj OBJECT ${COMMON_SRC})
target_compile_definitions(common-obj PRIVATE ${PRIVATE_COMPILE_DEFINITIONS} PUBLIC ${PUBLIC_COMPILE_DEFINITIONS})
target_include_directories(common-obj PRIVATE ${PROJECT_SOURCE_DIR} ${PROJECT_SOURCE_DIR}/include ${PORT_INCLUDE_DIR})

add_library(client-obj OBJECT ${CLIENT_SRC})
target_compile_definitions(client-obj PRIVATE ${PRIVATE_COMPILE_DEFINITIONS} PUBLIC ${PUBLIC_COMPILE_DEFINITIONS} "OC_CLIENT")
target_include_directories(client-obj PRIVATE ${PROJECT_SOURCE_DIR} ${PROJECT_SOURCE_DIR}/include ${PORT_INCLUDE_DIR})
if(OC_SECURITY_ENABLED)
    target_include_directories(client-obj PRIVATE ${MBEDTLS_INCLUDE_DIR})
endif()

add_library(server-obj OBJECT ${SERVER_SRC})
target_compile_definitions(server-obj PRIVATE ${PRIVATE_COMPILE_DEFINITIONS} PUBLIC ${PUBLIC_COMPILE_DEFINITIONS} "OC_SERVER")
target_include_directories(server-obj PRIVATE ${PROJECT_SOURCE_DIR} ${PROJECT_SOURCE_DIR}/include ${PORT_INCLUDE_DIR})
if(OC_SECURITY_ENABLED)
    target_include_directories(server-obj PRIVATE ${MBEDTLS_INCLUDE_DIR})
endif()

add_library(client-server-obj OBJECT ${CLIENT_SRC})
target_compile_definitions(client-server-obj PRIVATE ${PRIVATE_COMPILE_DEFINITIONS} PUBLIC ${PUBLIC_COMPILE_DEFINITIONS} "OC_CLIENT" "OC_SERVER")
target_include_directories(client-server-obj PRIVATE ${PROJECT_SOURCE_DIR} ${PROJECT_SOURCE_DIR}/include ${PORT_INCLUDE_DIR})
if(OC_SECURITY_ENABLED)
    target_include_directories(client-server-obj PRIVATE ${MBEDTLS_INCLUDE_DIR})
endif()

if(OC_CLOUD_ENABLED)
    add_library(cloud-obj OBJECT ${CLOUD_SRC})
    target_compile_definitions(cloud-obj PRIVATE ${PRIVATE_COMPILE_DEFINITIONS} PUBLIC ${PUBLIC_COMPILE_DEFINITIONS})
    target_include_directories(cloud-obj PRIVATE ${PROJECT_SOURCE_DIR} ${PROJECT_SOURCE_DIR}/include ${PORT_INCLUDE_DIR})
    if(OC_SECURITY_ENABLED)
        target_include_directories(cloud-obj PRIVATE ${MBEDTLS_INCLUDE_DIR})
    endif()
endif()

######## Compose static and shared libraries ########
# Client
set(client-lib-obj
    $<TARGET_OBJECTS:common-obj>
    $<TARGET_OBJECTS:tinycbor-master>
    $<TARGET_OBJECTS:client-obj>
)
if(OC_SECURITY_ENABLED)
    list(APPEND client-lib-obj $<TARGET_OBJECTS:mbedtls>)
endif()
add_library(client-static STATIC ${client-lib-obj})
target_link_libraries(client-static PRIVATE ${PRIVATE_LINK_LIBS})
target_compile_definitions(client-static PUBLIC
    $<BUILD_INTERFACE:${PUBLIC_COMPILE_DEFINITIONS};OC_CLIENT>
    $<INSTALL_INTERFACE:${PUBLIC_COMPILE_DEFINITIONS};OC_CLIENT>
)
target_include_directories(client-static PUBLIC
    $<BUILD_INTERFACE:.;include;${PORT_INCLUDE_DIR}>
    $<INSTALL_INTERFACE:include/iotivity-lite>
)
if(OC_SECURITY_ENABLED)
    target_include_directories(client-static PUBLIC $<BUILD_INTERFACE:${MBEDTLS_INCLUDE_DIR}>)
endif()
set_target_properties(client-static PROPERTIES
    OUTPUT_NAME "iotivity-lite-client"
    VERSION ${PROJECT_VERSION}
)

add_library(client-shared SHARED ${client-lib-obj})
target_link_libraries(client-shared PRIVATE ${PRIVATE_LINK_LIBS})
target_compile_definitions(client-shared PUBLIC
    $<BUILD_INTERFACE:${PUBLIC_COMPILE_DEFINITIONS};OC_CLIENT>
    $<INSTALL_INTERFACE:${PUBLIC_COMPILE_DEFINITIONS};OC_CLIENT>
)
target_include_directories(client-shared PUBLIC
    $<BUILD_INTERFACE:.;include;${PORT_INCLUDE_DIR}>
    $<INSTALL_INTERFACE:include/iotivity-lite>
)
if(OC_SECURITY_ENABLED)
    target_include_directories(client-shared PUBLIC $<BUILD_INTERFACE:${MBEDTLS_INCLUDE_DIR}>)
endif()
set_target_properties(client-shared PROPERTIES
    OUTPUT_NAME "iotivity-lite-client"
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
)

# Server
set(server-lib-obj
    $<TARGET_OBJECTS:common-obj>
    $<TARGET_OBJECTS:tinycbor-master>
    $<TARGET_OBJECTS:server-obj>
)
if(OC_CLOUD_ENABLED)
    list(APPEND server-lib-obj $<TARGET_OBJECTS:cloud-obj>)
endif()
if(OC_SECURITY_ENABLED)
    list(APPEND server-lib-obj $<TARGET_OBJECTS:mbedtls>)
endif()

add_library(server-static STATIC ${server-lib-obj})
target_link_libraries(server-static PRIVATE ${PRIVATE_LINK_LIBS})
target_compile_definitions(server-static PUBLIC
    $<BUILD_INTERFACE:${PUBLIC_COMPILE_DEFINITIONS};OC_SERVER>
    $<INSTALL_INTERFACE:${PUBLIC_COMPILE_DEFINITIONS};OC_SERVER>
)
target_include_directories(server-static PUBLIC
    $<BUILD_INTERFACE:.;include;${PORT_INCLUDE_DIR}>
    $<INSTALL_INTERFACE:include/iotivity-lite>
)
if(OC_SECURITY_ENABLED)
    target_include_directories(server-static PUBLIC $<BUILD_INTERFACE:${MBEDTLS_INCLUDE_DIR}>)
endif()
if(OC_CLOUD_ENABLED)
    target_include_directories(server-static PUBLIC $<BUILD_INTERFACE:${CLOUD_INCLUDE_DIR}>)
endif()
set_target_properties(server-static PROPERTIES
    OUTPUT_NAME "iotivity-lite-server"
    VERSION ${PROJECT_VERSION}
)

add_library(server-shared SHARED ${server-lib-obj})
target_link_libraries(server-shared PRIVATE ${PRIVATE_LINK_LIBS})
target_compile_definitions(server-shared PUBLIC
    $<BUILD_INTERFACE:${PUBLIC_COMPILE_DEFINITIONS};OC_SERVER>
    $<INSTALL_INTERFACE:${PUBLIC_COMPILE_DEFINITIONS};OC_SERVER>
)
target_include_directories(server-shared PUBLIC
    $<BUILD_INTERFACE:.;include;${PORT_INCLUDE_DIR}>
    $<INSTALL_INTERFACE:include/iotivity-lite>
)
if(OC_SECURITY_ENABLED)
    target_include_directories(server-shared PUBLIC $<BUILD_INTERFACE:${MBEDTLS_INCLUDE_DIR}>)
endif()
if(OC_CLOUD_ENABLED)
    target_include_directories(server-shared PUBLIC $<BUILD_INTERFACE:${CLOUD_INCLUDE_DIR}>)
endif()
set_target_properties(server-shared PROPERTIES
    OUTPUT_NAME "iotivity-lite-server"
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
)

# Client-Server
set(client-server-lib-obj
    $<TARGET_OBJECTS:common-obj>
    $<TARGET_OBJECTS:tinycbor-master>
    $<TARGET_OBJECTS:client-server-obj>
)
if(OC_CLOUD_ENABLED)
    list(APPEND client-server-lib-obj $<TARGET_OBJECTS:cloud-obj>)
endif()
if(OC_SECURITY_ENABLED)
    list(APPEND client-server-lib-obj $<TARGET_OBJECTS:mbedtls>)
endif()
add_library(client-server-static STATIC ${client-server-lib-obj})
target_link_libraries(client-server-static PRIVATE ${PRIVATE_LINK_LIBS})
target_compile_definitions(client-server-static PUBLIC
    $<BUILD_INTERFACE:${PUBLIC_COMPILE_DEFINITIONS};OC_CLIENT;OC_SERVER>
    $<INSTALL_INTERFACE:${PUBLIC_COMPILE_DEFINITIONS};OC_CLIENT;OC_SERVER>
)
target_include_directories(client-server-static PUBLIC
    $<BUILD_INTERFACE:.;include;${PORT_INCLUDE_DIR}>
    $<INSTALL_INTERFACE:include/iotivity-lite>
)
if(OC_SECURITY_ENABLED)
    target_include_directories(client-server-static PUBLIC $<BUILD_INTERFACE:${MBEDTLS_INCLUDE_DIR}>)
endif()
if(OC_CLOUD_ENABLED)
    target_include_directories(client-server-static PUBLIC $<BUILD_INTERFACE:${CLOUD_INCLUDE_DIR}>)
endif()
set_target_properties(client-server-static PROPERTIES
    OUTPUT_NAME "iotivity-lite-client-server"
    VERSION ${PROJECT_VERSION}
)

add_library(client-server-shared SHARED ${client-server-lib-obj})
target_link_libraries(client-server-shared PRIVATE ${PRIVATE_LINK_LIBS})
target_compile_definitions(client-server-shared PUBLIC
    $<BUILD_INTERFACE:${PUBLIC_COMPILE_DEFINITIONS};OC_CLIENT;OC_SERVER>
    $<INSTALL_INTERFACE:${PUBLIC_COMPILE_DEFINITIONS};OC_CLIENT;OC_SERVER>
)
target_include_directories(client-server-shared PUBLIC
    $<BUILD_INTERFACE:.;include;${PORT_INCLUDE_DIR}>
    $<INSTALL_INTERFACE:include/iotivity-lite>
)
if(OC_SECURITY_ENABLED)
    target_include_directories(client-server-shared PUBLIC $<BUILD_INTERFACE:${MBEDTLS_INCLUDE_DIR}>)
endif()
if(OC_CLOUD_ENABLED)
    target_include_directories(client-server-shared PUBLIC $<BUILD_INTERFACE:${CLOUD_INCLUDE_DIR}>)
endif()
set_target_properties(client-server-shared PROPERTIES
    OUTPUT_NAME "iotivity-lite-client-server"
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
)

######## Units tests (UNIX only) ########
include(CTest)
if(BUILD_TESTING AND UNIX)
    enable_language(CXX)
    set(CMAKE_CXX_STANDARD 11)
    set(CMAKE_CXX_STANDARD_REQUIRED ON)
    set(CMAKE_CXX_EXTENSIONS OFF)
    list(APPEND TEST_COMPILE_OPTIONS "-Wall" "-Wextra" "-fpermissive")
    list(APPEND TEST_LINK_LIBS client-server-static gtest_main Threads::Threads)
    if(CMAKE_COMPILER_IS_GNUCXX)
        list(APPEND TEST_COMPILE_OPTIONS "-fprofile-arcs" "-ftest-coverage")
        list(APPEND TEST_LINK_LIBS gcov)
    endif()

    # Build googletest
    add_subdirectory(${PROJECT_SOURCE_DIR}/deps/gtest gtest)

    # Helper macro to build unit test
    macro(package_add_test TESTNAME)
        add_executable(${TESTNAME} ${ARGN})
        target_compile_options(${TESTNAME} PRIVATE ${TEST_COMPILE_OPTIONS})
        target_compile_features(${TESTNAME} PRIVATE cxx_nullptr)
        target_compile_definitions(${TESTNAME} PRIVATE ${PUBLIC_COMPILE_DEFINITIONS} "OC_CLIENT" "OC_SERVER")
        target_include_directories(${TESTNAME} SYSTEM PRIVATE ${PROJECT_SOURCE_DIR}/deps/gtest/include)
        target_include_directories(${TESTNAME} PRIVATE
            ${PROJECT_SOURCE_DIR}
            ${PROJECT_SOURCE_DIR}/include
            ${PORT_INCLUDE_DIR}
            ${PROJECT_SOURCE_DIR}/messaging/coap
        )
        if(OC_SECURITY_ENABLED)
            target_include_directories(${TESTNAME} PRIVATE
                ${PROJECT_SOURCE_DIR}/security
                ${PROJECT_SOURCE_DIR}/deps/mbedtls/include
            )
        endif()
        if(OC_CLOUD_ENABLED)
            target_include_directories(${TESTNAME} PRIVATE ${PROJECT_SOURCE_DIR}/api/cloud)
        endif()
        target_link_libraries(${TESTNAME} PRIVATE ${TEST_LINK_LIBS})
        add_test(NAME ${TESTNAME} COMMAND ${TESTNAME})
        set_target_properties(${TESTNAME} PROPERTIES FOLDER unittests)
    endmacro()

    # Unit tests
    file(GLOB APITEST_SRC api/unittest/*.cpp)
    package_add_test(apitest ${APITEST_SRC})

    file(GLOB PLATFORMTEST_SRC port/unittest/*.cpp)
    file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/storage_test)
    package_add_test(platformtest ${PLATFORMTEST_SRC})

    file(GLOB MESSAGINGTEST_SRC messaging/coap/unittest/*.cpp)
    package_add_test(messagingtest ${MESSAGINGTEST_SRC})

    if(OC_SECURITY_ENABLED)
        file(GLOB SECURITYTEST_SRC security/unittest/*.cpp)
        package_add_test(securitytest ${SECURITYTEST_SRC})
    endif()

# Currently disabled because it hangs on TestCloudManager.cloud_manager_start_initialized_f
#    if(OC_CLOUD_ENABLED)
#        file(GLOB CLOUDTEST_SRC api/cloud/unittest/*.cpp)
#        package_add_test(cloudtest ${CLOUDTEST_SRC})
#    endif()
endif()

######## Generate pkg-config and cmake package files ########
foreach(cflag IN LISTS PUBLIC_COMPILE_DEFINITIONS)
    string(APPEND extra_cflags "-D${cflag} ")
endforeach()

# Generate pkg-config files
set(prefix ${CMAKE_INSTALL_PREFIX})
set(exec_prefix "\${prefix}")
set(libdir "\${prefix}/${CMAKE_INSTALL_LIBDIR}")
set(includedir "\${prefix}/${CMAKE_INSTALL_INCLUDEDIR}")
set(version ${iotivity-lite_VERSION})

set(PKG_CONFIG_FILES
    iotivity-lite-client.pc
    iotivity-lite-server.pc
    iotivity-lite-client-server.pc)
foreach(pkg-config-file IN LISTS PKG_CONFIG_FILES)
    configure_file(
        "${PROJECT_SOURCE_DIR}/port/linux/${pkg-config-file}.in"
        ${pkg-config-file}
        @ONLY)
endforeach()

include(CMakePackageConfigHelpers)
configure_package_config_file(iotivity-liteConfig.cmake.in
  ${CMAKE_CURRENT_BINARY_DIR}/iotivity-liteConfig.cmake
  INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/iotivity-lite
)
write_basic_package_version_file(iotivity-liteConfigVersion.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

######## Installation ########
# Libraries
install(TARGETS
    client-static client-shared
    server-static server-shared
    client-server-static client-server-shared
    EXPORT iotivity-liteTARGETS
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR} COMPONENT bin
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR} COMPONENT lib
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR} COMPONENT dev
)

# pkg-config files
foreach(pkg-config-file IN LISTS PKG_CONFIG_FILES)
    install(FILES ${CMAKE_CURRENT_BINARY_DIR}/${pkg-config-file}
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig COMPONENT dev)
endforeach()

# CMake package
if(WIN32 AND NOT CYGWIN)
    set(TARGETS_INSTALL_DIR CMake)
else()
    set(TARGETS_INSTALL_DIR ${CMAKE_INSTALL_LIBDIR}/cmake/iotivity-lite)
endif()
install(EXPORT iotivity-liteTARGETS
    FILE
        iotivity-liteTargets.cmake
    NAMESPACE
        iotivity-lite::
    DESTINATION
        ${TARGETS_INSTALL_DIR}
    COMPONENT dev
)
install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/iotivity-liteConfig.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/iotivity-liteConfigVersion.cmake
    DESTINATION ${TARGETS_INSTALL_DIR}
)

# Header files
install(DIRECTORY include/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/iotivity-lite COMPONENT dev
    FILES_MATCHING PATTERN "*.h"
)
install(DIRECTORY ${PROJECT_SOURCE_DIR}/port
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/iotivity-lite COMPONENT dev
    FILES_MATCHING PATTERN "*.h"
)
install(FILES ${PORT_INCLUDE_DIR}/oc_config.h
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/iotivity-lite COMPONENT dev
)
install(DIRECTORY util
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/iotivity-lite COMPONENT dev
    FILES_MATCHING PATTERN "*.h"
)
install(DIRECTORY messaging/coap/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/iotivity-lite/messaging/coap COMPONENT dev
    FILES_MATCHING PATTERN "*.h"
    PATTERN "unittest" EXCLUDE
)

######## Code formatting ########
if(PROJECT_SOURCE_DIR STREQUAL CMAKE_SOURCE_DIR)
    # Add clang-format target
    add_custom_target(format
        COMMAND ${CMAKE_COMMAND} -P ${PROJECT_SOURCE_DIR}/tools/clang-format.cmake
        WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
    )
endif()
