cmake_minimum_required (VERSION 3.10)
project(iotivity-lite VERSION 2.2.5)

include(GNUInstallDirs) # Installation directories for `install` command and pkgconfig file

set(BUILD_SHARED_LIBS ON CACHE BOOL "Build shared libraries")
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

if(OC_CLOUD_ENABLED)
    target_sources(iotivity-api INTERFACE
        ${PROJECT_SOURCE_DIR}/api/cloud/oc_cloud_manager.c
        ${PROJECT_SOURCE_DIR}/api/cloud/oc_cloud_rd.c
        ${PROJECT_SOURCE_DIR}/api/cloud/oc_cloud_resource.c
        ${PROJECT_SOURCE_DIR}/api/cloud/oc_cloud_store.c
        ${PROJECT_SOURCE_DIR}/api/cloud/oc_cloud.c
        ${PROJECT_SOURCE_DIR}/api/cloud/rd_client.c
        ${PROJECT_SOURCE_DIR}/api/cloud/oc_cloud_apis.c
    )
endif()

target_include_directories(iotivity-api INTERFACE
    ${PROJECT_SOURCE_DIR}/
    ${PROJECT_SOURCE_DIR}/api
    ${PROJECT_SOURCE_DIR}/api/c-timestamp
    ${PROJECT_SOURCE_DIR}/include
)
# do not treat warnings as errors on Windows
# block should be defined after the target library
if(MSVC)
    target_compile_options(iotivity-api INTERFACE /W1 /WX-)
endif()

# Core functions used by Iotivity
add_library(iotivity-common INTERFACE)

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

install(DIRECTORY messaging/coap/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/iotivity-lite/messaging/coap COMPONENT dev
    FILES_MATCHING PATTERN "*.h"
    PATTERN "unittest" EXCLUDE
)

set(PUBLIC_LINK_LIBS "")
if(BUILD_SHARED_LIBS)
    list(APPEND PUBLIC_LINK_LIBS "mbedtls")
    list(APPEND PUBLIC_LINK_LIBS "mbedcrypto")
    list(APPEND PUBLIC_LINK_LIBS "mbedx509")
endif()

set(PUBLIC_COMPILER_DEFS "")
if(OC_DYNAMIC_ALLOCATION_ENABLED)
    target_compile_definitions(iotivity-common INTERFACE OC_DYNAMIC_ALLOCATION)
    list(APPEND PUBLIC_COMPILER_DEFS "OC_DYNAMIC_ALLOCATION")
endif()

if(OC_SECURITY_ENABLED)
    target_compile_definitions(iotivity-common INTERFACE OC_SECURITY)
    list(APPEND PUBLIC_COMPILER_DEFS "OC_SECURITY")
endif()

if(OC_PKI_ENABLED)
    target_compile_definitions(iotivity-common INTERFACE OC_PKI)
    list(APPEND PUBLIC_COMPILER_DEFS "OC_PKI")
endif()

if(OC_DEBUG_ENABLED)
    target_compile_definitions(iotivity-common INTERFACE OC_DEBUG)
endif()

if(OC_CLOUD_ENABLED)
    target_compile_definitions(iotivity-common INTERFACE OC_CLOUD)
    list(APPEND PUBLIC_COMPILER_DEFS "OC_CLOUD")
endif()

if(OC_IDD_API_ENABLED)
    target_compile_definitions(iotivity-common INTERFACE OC_IDD_API)
endif()

if(OC_TCP_ENABLED)
    target_compile_definitions(iotivity-common INTERFACE OC_TCP)
    list(APPEND PUBLIC_COMPILER_DEFS "OC_TCP")
endif()

if(OC_DISCOVERY_RESOURCE_OBSERVABLE_ENABLED)
    target_compile_definitions(iotivity-common INTERFACE OC_DISCOVERY_RESOURCE_OBSERVABLE)
endif()

if(OC_REPRESENTATION_REALLOC_ENCODING_ENABLED)
    target_compile_definitions(iotivity-common INTERFACE OC_REP_ENCODING_REALLOC)
endif()

if(OC_COLLECTIONS_IF_CREATE_ENABLED)
    target_compile_definitions(iotivity-common INTERFACE OC_COLLECTIONS_IF_CREATE)
    list(APPEND PUBLIC_COMPILER_DEFS "OC_COLLECTIONS_IF_CREATE")
endif()

if(OC_MNT_ENABLED)
    target_compile_definitions(iotivity-common INTERFACE OC_MNT)
    list(APPEND PUBLIC_COMPILER_DEFS "OC_MNT")
endif()

if(OC_SOFTWARE_UPDATE_ENABLED)
    target_compile_definitions(iotivity-common INTERFACE OC_SOFTWARE_UPDATE)
    list(APPEND PUBLIC_COMPILER_DEFS "OC_SOFTWARE_UPDATE")
endif()

if(OC_WKCORE_ENABLED)
    target_compile_definitions(iotivity-common INTERFACE OC_WKCORE)
    list(APPEND PUBLIC_COMPILER_DEFS "OC_WKCORE")
endif()

if(OC_OSCORE_ENABLED)
    target_compile_definitions(iotivity-common INTERFACE OC_OSCORE)
    list(APPEND PUBLIC_COMPILER_DEFS "OC_OSCORE")
endif()

if(OC_IPV4_ENABLED)
    target_compile_definitions(iotivity-common INTERFACE OC_IPV4)
    list(APPEND PUBLIC_COMPILER_DEFS "OC_IPV4")
endif()

# Client and server versions of Iotivity
add_library(iotivity-lite-client)
target_compile_definitions(iotivity-lite-client PUBLIC OC_CLIENT)
target_link_libraries(iotivity-lite-client PRIVATE
    iotivity-coap
)
target_link_libraries(iotivity-lite-client PUBLIC
    iotivity-common
    iotivity-api
)
if(BUILD_SHARED_LIBS)
    set_target_properties(iotivity-lite-client
        PROPERTIES
        VERSION "${PROJECT_VERSION}"
        SOVERSION "${PROJECT_VERSION_MAJOR}"
    )
endif()
install(TARGETS iotivity-lite-client EXPORT iotivity-lite-clientTargets
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR} COMPONENT runtime
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR} COMPONENT runtime
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR} COMPONENT dev
)

add_library(iotivity-lite-server)
target_compile_definitions(iotivity-lite-server PUBLIC OC_SERVER)
target_link_libraries(iotivity-lite-server PRIVATE
    iotivity-coap
)
target_link_libraries(iotivity-lite-server PUBLIC
    iotivity-common
    iotivity-api
)
if(BUILD_SHARED_LIBS)
    set_target_properties(iotivity-lite-server
        PROPERTIES
        VERSION "${PROJECT_VERSION}"
        SOVERSION "${PROJECT_VERSION_MAJOR}"
    )
endif()
install(TARGETS iotivity-lite-server EXPORT iotivity-lite-serverTargets
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR} COMPONENT runtime
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR} COMPONENT runtime
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR} COMPONENT dev
)

add_library(iotivity-lite-client-server)
target_compile_definitions(iotivity-lite-client-server PUBLIC OC_SERVER OC_CLIENT)
target_link_libraries(iotivity-lite-client-server PRIVATE
    iotivity-coap
)
target_link_libraries(iotivity-lite-client-server PUBLIC
    iotivity-common
    iotivity-api
)
if(BUILD_SHARED_LIBS)
    set_target_properties(iotivity-lite-client-server
        PROPERTIES
        VERSION "${PROJECT_VERSION}"
        SOVERSION "${PROJECT_VERSION_MAJOR}"
    )
endif()
install(TARGETS iotivity-lite-client-server EXPORT iotivity-lite-client-serverTargets
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR} COMPONENT runtime
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR} COMPONENT runtime
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR} COMPONENT dev
)
# install headers
install(DIRECTORY include/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/iotivity-lite COMPONENT dev
    FILES_MATCHING PATTERN "*.h"
)
install(DIRECTORY util
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/iotivity-lite
    FILES_MATCHING PATTERN "*.h"
)

if(PROJECT_SOURCE_DIR STREQUAL CMAKE_SOURCE_DIR)
    # Add clang-format target
    add_custom_target(format
        COMMAND ${CMAKE_COMMAND} -P ${PROJECT_SOURCE_DIR}/tools/clang-format.cmake
        WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
    )
endif()

add_subdirectory(port)
add_subdirectory(apps)
add_subdirectory(onboarding_tool)
add_subdirectory(deps)
