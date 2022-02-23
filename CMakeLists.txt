cmake_minimum_required (VERSION 3.10)
project(iotivity-lite VERSION 2.2.5)

set(CMAKE_BINARY_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../build_${PROJECT_NAME}_${CMAKE_BUILD_TYPE})
set(CMAKE_INSTALL_PREFIX ${CMAKE_BINARY_DIR}/install CACHE PATH "Path to libraries and binaries" FORCE)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_INSTALL_PREFIX}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_INSTALL_PREFIX}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_INSTALL_PREFIX}/bin)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

# Patch mbedtls
set(OC_REAPPLY_MBEDTLS_PATCHES ON CACHE BOOL "")
if(OC_REAPPLY_MBEDTLS_PATCHES)
    include(mbedtls-patch.cmake)
    set(OC_REAPPLY_MBEDTLS_PATCHES OFF CACHE BOOL 
        "By default, mbedTLS patches are applied upon the first CMake Configure. Set this to ON to reapply the patches on the next configure."
         FORCE
    )
endif()

# Do not build anything except for the library
option(ENABLE_PROGRAMS "Build mbed TLS programs." OFF)
option(ENABLE_TESTING "Build mbed TLS tests." OFF)

######## Build configuration options ########
set(BUILD_EXAMPLE_APPLICATIONS ON CACHE BOOL "Build example applications.")
set(OC_DYNAMIC_ALLOCATION_ENABLED ON CACHE BOOL "Enable dynamic memory allocation within the OCF stack and MBedtls.")
set(OC_SECURITY_ENABLED OFF CACHE BOOL "Enable security")
set(OC_PKI_ENABLED OFF CACHE BOOL "Enable PKI security")
set(OC_CLOUD_ENABLED OFF CACHE BOOL "Enable cloud communications")
set(OC_DEBUG_ENABLED OFF CACHE BOOL "Enable debug messages")
set(OC_IDD_API_ENABLED ON CACHE BOOL "Enable the Introspection Device Data API")
set(OC_TCP_ENABLED ON CACHE BOOL "Enable tcp")
set(OC_IPV4_ENABLED ON CACHE BOOL "Enable ipv4")

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

set(OC_CLANG_TIDY_ENABLED OFF CACHE BOOL "Enable clang-tidy analysis during compilation.")

target_include_directories(mbedcrypto PUBLIC
    ${PROJECT_SOURCE_DIR}
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/deps/mbedtls/include
)

if(TARGET mbedcrypto-plat)
	target_link_libraries(mbedcrypto mbedcrypto-plat)
endif()


# Iotivity API
add_library(iotivity-api INTERFACE)

target_sources(iotivity-api INTERFACE
    ${PROJECT_SOURCE_DIR}/api/oc_base64.c
    ${PROJECT_SOURCE_DIR}/api/oc_blockwise.c
    ${PROJECT_SOURCE_DIR}/api/oc_buffer.c
    ${PROJECT_SOURCE_DIR}/api/oc_client_api.c
    ${PROJECT_SOURCE_DIR}/api/oc_clock.c
    ${PROJECT_SOURCE_DIR}/api/oc_collection.c
    ${PROJECT_SOURCE_DIR}/api/oc_core_res.c
    ${PROJECT_SOURCE_DIR}/api/oc_discovery.c
    ${PROJECT_SOURCE_DIR}/api/oc_endpoint.c
    ${PROJECT_SOURCE_DIR}/api/oc_enums.c
    ${PROJECT_SOURCE_DIR}/api/oc_helpers.c
    ${PROJECT_SOURCE_DIR}/api/oc_main.c
    ${PROJECT_SOURCE_DIR}/api/oc_mnt.c
    ${PROJECT_SOURCE_DIR}/api/oc_network_events.c
    ${PROJECT_SOURCE_DIR}/api/oc_rep.c
    ${PROJECT_SOURCE_DIR}/api/oc_resource_factory.c
    ${PROJECT_SOURCE_DIR}/api/oc_ri.c
    ${PROJECT_SOURCE_DIR}/api/oc_server_api.c
    ${PROJECT_SOURCE_DIR}/api/oc_session_events.c
    ${PROJECT_SOURCE_DIR}/api/oc_swupdate.c
    ${PROJECT_SOURCE_DIR}/api/oc_uuid.c
    ${PROJECT_SOURCE_DIR}/api/c-timestamp/timestamp_compare.c
    ${PROJECT_SOURCE_DIR}/api/c-timestamp/timestamp_format.c
    ${PROJECT_SOURCE_DIR}/api/c-timestamp/timestamp_parse.c
    ${PROJECT_SOURCE_DIR}/api/c-timestamp/timestamp_tm.c
    ${PROJECT_SOURCE_DIR}/api/c-timestamp/timestamp_valid.c
)

target_include_directories(iotivity-api INTERFACE
    ${PROJECT_SOURCE_DIR}/
    ${PROJECT_SOURCE_DIR}/api
    ${PROJECT_SOURCE_DIR}/api/c-timestamp
    ${PROJECT_SOURCE_DIR}/include
)

target_link_libraries(iotivity-api INTERFACE json-parser)

# Core functions used by Iotivity
add_library(iotivity-common INTERFACE)


# do not treat warnings as errors on Windows
# block should be defined after the target library
if(MSVC)
    target_compile_options(mbedtls PRIVATE /W1 /WX-)
    target_compile_options(mbedx509 PRIVATE /W1 /WX-)
    target_compile_options(mbedcrypto PRIVATE /W1 /WX-)
    target_compile_options(iotivity-api INTERFACE /W1 /WX-)
endif()

target_sources(iotivity-common INTERFACE
    # Utilities that are used deep within Iotivity
    ${PROJECT_SOURCE_DIR}/util/oc_etimer.c
    ${PROJECT_SOURCE_DIR}/util/oc_list.c
    ${PROJECT_SOURCE_DIR}/util/oc_memb.c
    ${PROJECT_SOURCE_DIR}/util/oc_mem_trace.c
    ${PROJECT_SOURCE_DIR}/util/oc_mmem.c
    ${PROJECT_SOURCE_DIR}/util/oc_process.c
    ${PROJECT_SOURCE_DIR}/util/oc_timer.c
    # Security
    ${PROJECT_SOURCE_DIR}/security/oc_acl.c
    ${PROJECT_SOURCE_DIR}/security/oc_ael.c
    ${PROJECT_SOURCE_DIR}/security/oc_audit.c
    ${PROJECT_SOURCE_DIR}/security/oc_certs.c
    ${PROJECT_SOURCE_DIR}/security/oc_cred.c
    ${PROJECT_SOURCE_DIR}/security/oc_csr.c
    ${PROJECT_SOURCE_DIR}/security/oc_doxm.c
    ${PROJECT_SOURCE_DIR}/security/oc_keypair.c
    ${PROJECT_SOURCE_DIR}/security/oc_obt.c
    ${PROJECT_SOURCE_DIR}/security/oc_obt_certs.c
    ${PROJECT_SOURCE_DIR}/security/oc_obt_otm_cert.c
    ${PROJECT_SOURCE_DIR}/security/oc_obt_otm_justworks.c
    ${PROJECT_SOURCE_DIR}/security/oc_obt_otm_randompin.c
    ${PROJECT_SOURCE_DIR}/security/oc_pki.c
    ${PROJECT_SOURCE_DIR}/security/oc_pstat.c
    ${PROJECT_SOURCE_DIR}/security/oc_roles.c
    ${PROJECT_SOURCE_DIR}/security/oc_sdi.c
    ${PROJECT_SOURCE_DIR}/security/oc_sp.c
    ${PROJECT_SOURCE_DIR}/security/oc_store.c
    ${PROJECT_SOURCE_DIR}/security/oc_svr.c
    ${PROJECT_SOURCE_DIR}/security/oc_tls.c

)

target_include_directories(iotivity-common INTERFACE
    ${PROJECT_SOURCE_DIR}/
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/deps/tinycbor/src
    ${PROJECT_SOURCE_DIR}/security
)

target_link_libraries(iotivity-common INTERFACE iotivity-port mbedtls tinycbor-master)

# Iotivity's implementation of CoAP
add_library(iotivity-coap INTERFACE)

target_sources(iotivity-coap INTERFACE
    ${PROJECT_SOURCE_DIR}/messaging/coap/coap.c
    ${PROJECT_SOURCE_DIR}/messaging/coap/coap_signal.c
    ${PROJECT_SOURCE_DIR}/messaging/coap/engine.c
    ${PROJECT_SOURCE_DIR}/messaging/coap/observe.c
    ${PROJECT_SOURCE_DIR}/messaging/coap/separate.c
    ${PROJECT_SOURCE_DIR}/messaging/coap/transactions.c
)

target_include_directories(iotivity-coap INTERFACE
    ${PROJECT_SOURCE_DIR}/messaging/coap/
)

target_link_libraries(iotivity-coap INTERFACE iotivity-port)

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

if(OC_IPV4_ENABLED)
    target_compile_definitions(iotivity-common INTERFACE OC_IPV4)
endif()

# Client and server versions of Iotivity
add_library(iotivity-client)
target_compile_definitions(iotivity-client PUBLIC OC_CLIENT)
target_link_libraries(iotivity-client PRIVATE
    iotivity-coap
    iotivity-api
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
    file(GLOB SECURITY_OBT_SRC
        ${PROJECT_SOURCE_DIR}/security/oc_obt*.c
    )
    list(REMOVE_ITEM SECURITY_SRC
        ${SECURITY_OBT_SRC}
    )
    list(APPEND SERVER_SRC ${SECURITY_SRC})
    list(APPEND CLIENT_SRC ${SECURITY_SRC})
    if(OC_DYNAMIC_ALLOCATION_ENABLED)
        list(APPEND CLIENT_SRC ${SECURITY_OBT_SRC})
    endif()
endif()

if(OC_CLOUD_ENABLED)
    file(GLOB CLOUD_SRC api/cloud/*.c)
    set(CLOUD_INCLUDE_DIR ${PROJECT_SOURCE_DIR}/api/cloud)
endif()

file(GLOB PYTHON_SRC python/*.c)

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
    get_target_property(MBEDTLS_INCLUDE_DIRS mbedtls INCLUDE_DIRECTORIES)
endif()

# enable clang-tidy for iotivity targets
oc_enable_clang_tidy()

add_library(common-obj OBJECT ${COMMON_SRC})
target_compile_definitions(common-obj PRIVATE ${PRIVATE_COMPILE_DEFINITIONS} PUBLIC ${PUBLIC_COMPILE_DEFINITIONS})
target_include_directories(common-obj PRIVATE ${PROJECT_SOURCE_DIR} ${PROJECT_SOURCE_DIR}/include ${PROJECT_SOURCE_DIR}/port ${PORT_INCLUDE_DIR})

add_library(client-obj OBJECT ${CLIENT_SRC})
target_compile_definitions(client-obj PRIVATE ${PRIVATE_COMPILE_DEFINITIONS} PUBLIC ${PUBLIC_COMPILE_DEFINITIONS} "OC_CLIENT")
target_include_directories(client-obj PRIVATE ${PROJECT_SOURCE_DIR} ${PROJECT_SOURCE_DIR}/include ${PROJECT_SOURCE_DIR}/port ${PORT_INCLUDE_DIR})
if(OC_SECURITY_ENABLED)
    target_include_directories(client-obj PRIVATE ${MBEDTLS_INCLUDE_DIRS})
endif()

add_library(server-obj OBJECT ${SERVER_SRC})
target_compile_definitions(server-obj PRIVATE ${PRIVATE_COMPILE_DEFINITIONS} PUBLIC ${PUBLIC_COMPILE_DEFINITIONS} "OC_SERVER")
target_include_directories(server-obj PRIVATE ${PROJECT_SOURCE_DIR} ${PROJECT_SOURCE_DIR}/include ${PROJECT_SOURCE_DIR}/port ${PORT_INCLUDE_DIR})
if(OC_SECURITY_ENABLED)
    target_include_directories(server-obj PRIVATE ${MBEDTLS_INCLUDE_DIRS})
endif()

add_library(client-server-obj OBJECT ${CLIENT_SRC})
target_compile_definitions(client-server-obj PRIVATE ${PRIVATE_COMPILE_DEFINITIONS} PUBLIC ${PUBLIC_COMPILE_DEFINITIONS} "OC_CLIENT" "OC_SERVER")
target_include_directories(client-server-obj PRIVATE ${PROJECT_SOURCE_DIR} ${PROJECT_SOURCE_DIR}/include ${PROJECT_SOURCE_DIR}/port ${PORT_INCLUDE_DIR})
if(OC_SECURITY_ENABLED)
    target_include_directories(client-server-obj PRIVATE ${MBEDTLS_INCLUDE_DIRS})
endif()

if(OC_CLOUD_ENABLED)
    add_library(cloud-obj OBJECT ${CLOUD_SRC})
    target_compile_definitions(cloud-obj PRIVATE ${PRIVATE_COMPILE_DEFINITIONS} PUBLIC ${PUBLIC_COMPILE_DEFINITIONS})
    target_include_directories(cloud-obj PRIVATE ${PROJECT_SOURCE_DIR} ${PROJECT_SOURCE_DIR}/include ${PROJECT_SOURCE_DIR}/port ${PORT_INCLUDE_DIR})
    if(OC_SECURITY_ENABLED)
        target_include_directories(cloud-obj PRIVATE ${MBEDTLS_INCLUDE_DIRS})
    endif()
endif()

add_library(python-obj OBJECT ${PYTHON_SRC})
target_compile_definitions(python-obj PRIVATE ${PRIVATE_COMPILE_DEFINITIONS} OC_LIBRARY_EXPORT PUBLIC ${PUBLIC_COMPILE_DEFINITIONS} "OC_LIBRARY" "OC_CLIENT")
set_property(TARGET python-obj PROPERTY C_VISIBILITY_PRESET hidden)
set_property(TARGET python-obj PROPERTY VISIBILITY_INLINES_HIDDEN ON)
target_include_directories(python-obj PRIVATE ${PROJECT_SOURCE_DIR} ${PROJECT_SOURCE_DIR}/include ${PROJECT_SOURCE_DIR}/port ${PORT_INCLUDE_DIR})
if(OC_SECURITY_ENABLED)
    target_include_directories(python-obj PRIVATE ${MBEDTLS_INCLUDE_DIRS})
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
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}>
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/port>
    $<BUILD_INTERFACE:${PORT_INCLUDE_DIR}>
    $<INSTALL_INTERFACE:include/iotivity-lite>
)
if(OC_SECURITY_ENABLED)
    target_include_directories(client-static PUBLIC "$<BUILD_INTERFACE:${MBEDTLS_INCLUDE_DIRS}>")
endif()
set_target_properties(client-static PROPERTIES
    OUTPUT_NAME "iotivity-lite-client-static"
    VERSION ${PROJECT_VERSION}
)

if(NOT MSVC)
    # Since the library symbols are not explicitly exported, no proper DLL and import LIB are generated with MSVC
    add_library(client-shared SHARED ${client-lib-obj})
    target_link_libraries(client-shared PRIVATE ${PRIVATE_LINK_LIBS})
    target_compile_definitions(client-shared PUBLIC
        $<BUILD_INTERFACE:${PUBLIC_COMPILE_DEFINITIONS};OC_CLIENT>
        $<INSTALL_INTERFACE:${PUBLIC_COMPILE_DEFINITIONS};OC_CLIENT>
    )
    target_include_directories(client-shared PUBLIC
        $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}>
        $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
        $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/port>
        $<BUILD_INTERFACE:${PORT_INCLUDE_DIR}>
        $<INSTALL_INTERFACE:include/iotivity-lite>
    )
    if(OC_SECURITY_ENABLED)
        target_include_directories(client-shared PUBLIC "$<BUILD_INTERFACE:${MBEDTLS_INCLUDE_DIRS}>")
    endif()
    set_target_properties(client-shared PROPERTIES
        OUTPUT_NAME "iotivity-lite-client"
        VERSION ${PROJECT_VERSION}
        SOVERSION ${PROJECT_VERSION_MAJOR}
    )
endif()

# Server
set(server-lib-obj
    $<TARGET_OBJECTS:common-obj>
    $<TARGET_OBJECTS:tinycbor-master>
    $<TARGET_OBJECTS:server-obj>
)
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
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}>
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/port>
    $<BUILD_INTERFACE:${PORT_INCLUDE_DIR}>
    $<INSTALL_INTERFACE:include/iotivity-lite>
)
if(OC_SECURITY_ENABLED)
    target_include_directories(server-static PUBLIC "$<BUILD_INTERFACE:${MBEDTLS_INCLUDE_DIRS}>")
endif()
set_target_properties(server-static PROPERTIES
    OUTPUT_NAME "iotivity-lite-server-static"
    VERSION ${PROJECT_VERSION}
)

if(NOT MSVC)
    # Since the library symbols are not explicitly exported, no proper DLL and import LIB are generated with MSVC
    add_library(server-shared SHARED ${server-lib-obj})
    target_link_libraries(server-shared PRIVATE ${PRIVATE_LINK_LIBS})
    target_compile_definitions(server-shared PUBLIC
        $<BUILD_INTERFACE:${PUBLIC_COMPILE_DEFINITIONS};OC_SERVER>
        $<INSTALL_INTERFACE:${PUBLIC_COMPILE_DEFINITIONS};OC_SERVER>
    )
    target_include_directories(server-shared PUBLIC
        $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}>
        $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
        $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/port>
        $<BUILD_INTERFACE:${PORT_INCLUDE_DIR}>
        $<INSTALL_INTERFACE:include/iotivity-lite>
    )
    if(OC_SECURITY_ENABLED)
        target_include_directories(server-shared PUBLIC "$<BUILD_INTERFACE:${MBEDTLS_INCLUDE_DIRS}>")
    endif()
    set_target_properties(server-shared PROPERTIES
        OUTPUT_NAME "iotivity-lite-server"
        VERSION ${PROJECT_VERSION}
        SOVERSION ${PROJECT_VERSION_MAJOR}
    )
endif()

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
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}>
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/port>
    $<BUILD_INTERFACE:${PORT_INCLUDE_DIR}>
    $<INSTALL_INTERFACE:include/iotivity-lite>
)
if(OC_SECURITY_ENABLED)
    target_include_directories(client-server-static PUBLIC "$<BUILD_INTERFACE:${MBEDTLS_INCLUDE_DIRS}>")
endif()
if(OC_CLOUD_ENABLED)
    target_include_directories(client-server-static PUBLIC $<BUILD_INTERFACE:${CLOUD_INCLUDE_DIR}>)
endif()
set_target_properties(client-server-static PROPERTIES
    OUTPUT_NAME "iotivity-lite-client-server-static"
    VERSION ${PROJECT_VERSION}
)

if(NOT MSVC)
    # Since the library symbols are not explicitly exported, no proper DLL and import LIB are generated with MSVC
    add_library(client-server-shared SHARED ${client-server-lib-obj})
    target_link_libraries(client-server-shared PRIVATE ${PRIVATE_LINK_LIBS})
    target_compile_definitions(client-server-shared PUBLIC
        $<BUILD_INTERFACE:${PUBLIC_COMPILE_DEFINITIONS};OC_CLIENT;OC_SERVER>
        $<INSTALL_INTERFACE:${PUBLIC_COMPILE_DEFINITIONS};OC_CLIENT;OC_SERVER>
    )
    target_include_directories(client-server-shared PUBLIC
        $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}>
        $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
        $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/port>
        $<BUILD_INTERFACE:${PORT_INCLUDE_DIR}>
        $<INSTALL_INTERFACE:include/iotivity-lite>
    )
    if(OC_SECURITY_ENABLED)
        target_include_directories(client-server-shared PUBLIC "$<BUILD_INTERFACE:${MBEDTLS_INCLUDE_DIRS}>")
    endif()
    if(OC_CLOUD_ENABLED)
        target_include_directories(client-server-shared PUBLIC $<BUILD_INTERFACE:${CLOUD_INCLUDE_DIR}>)
    endif()
    set_target_properties(client-server-shared PROPERTIES
        OUTPUT_NAME "iotivity-lite-client-server"
        VERSION ${PROJECT_VERSION}
        SOVERSION ${PROJECT_VERSION_MAJOR}
    )
endif()

# Python client
set(client-python-lib-obj
    $<TARGET_OBJECTS:common-obj>
    $<TARGET_OBJECTS:tinycbor-master>
    $<TARGET_OBJECTS:client-obj>
    $<TARGET_OBJECTS:python-obj>
)
if(OC_SECURITY_ENABLED)
    list(APPEND client-python-lib-obj $<TARGET_OBJECTS:mbedtls>)
endif()
add_library(client-python-shared SHARED ${client-python-lib-obj})
target_link_libraries(client-python-shared PRIVATE ${PRIVATE_LINK_LIBS})
target_compile_definitions(client-python-shared PUBLIC
    $<BUILD_INTERFACE:${PUBLIC_COMPILE_DEFINITIONS};OC_CLIENT>
    $<INSTALL_INTERFACE:${PUBLIC_COMPILE_DEFINITIONS};OC_CLIENT>
)
target_include_directories(client-python-shared PUBLIC
    $<BUILD_INTERFACE:.;include;port;${PORT_INCLUDE_DIR}>
    $<INSTALL_INTERFACE:include/iotivity-lite>
)
if(OC_SECURITY_ENABLED)
    target_include_directories(client-python-shared PUBLIC "$<BUILD_INTERFACE:${MBEDTLS_INCLUDE_DIRS}>")
endif()
set_target_properties(client-python-shared PROPERTIES
    OUTPUT_NAME "iotivity-lite-client-python"
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

    # Disable clang-tidy for gtest
    oc_disable_clang_tidy()

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

    # reenable clang-tidy for any remaining targets
    oc_enable_clang_tidy()
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
set(INSTALL_TARGETS
    client-static client-shared
    server-static server-shared
    client-server-static client-server-shared
)
if(MSVC)
    # Since the library symbols are not explicitly exported, no proper DLL and import LIB are generated with MSVC
    set(INSTALL_TARGETS
        client-static
        server-static
        client-server-static
    )
endif()
install(TARGETS ${INSTALL_TARGETS}
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

    # Add windows registry setting so cmake can find from installed location
    set(CMAKE_PACKAGE_REGISTRY_KEY "HKCU\\\\Software\\\\Kitware\\\\CMake\\\\Packages\\\\iotivity-lite")
    file(MD5 "${CMAKE_BINARY_DIR}/iotivity-liteConfig.cmake" INSTALL_HASH)
    install(CODE "execute_process(COMMAND reg add ${CMAKE_PACKAGE_REGISTRY_KEY} /v ${INSTALL_HASH} /t REG_SZ /d \"${CMAKE_INSTALL_PREFIX}\" /f)" COMPONENT dev)
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
    DESTINATION ${TARGETS_INSTALL_DIR} COMPONENT dev
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

add_subdirectory(port)
add_subdirectory(apps)
#add_subdirectory(onboarding_tool)
add_subdirectory(deps)
