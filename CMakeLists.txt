cmake_minimum_required (VERSION 3.10)
project(iotivity-lite)

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

set(OC_DYNAMIC_ALLOCATION_ENABLED ON CACHE BOOL "Enable dynamic memory allocation within the OCF stack and MBedtls.")
set(OC_SECURITY_ENABLED ON CACHE BOOL "Enable security.")
set(OC_PKI_ENABLED ON CACHE BOOL "Enable PKI security.")
set(OC_CLOUD_ENABLED OFF CACHE BOOL "Enable cloud communications.")
set(OC_DEBUG_ENABLED OFF CACHE BOOL "Enable debug messages.")
set(OC_IDD_API_ENABLED ON CACHE BOOL "Enable the Introspection Device Data API.")
set(OC_TCP_ENABLED ON CACHE BOOL "Enable OCF communications over TCP. Necessary for Cloud communications.")
set(OC_DISCOVERY_RESOURCE_OBSERVABLE_ENABLED OFF CACHE BOOL "Enable observation over oic/res resource.")
set(OC_REPRESENTATION_REALLOC_ENCODING_ENABLED OFF CACHE BOOL "Enable realloc during encoding the representation.")

# If an mbedtls platform layer is defined, add it to the mbedtls list of libs
if(TARGET mbedtls-plat)
    set(libs ${libs} mbedtls-plat)
endif()

add_subdirectory(${PROJECT_SOURCE_DIR}/deps/mbedtls)

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
    target_compile_definitions(iotivity-common INTERFACE OC_DEBUG)
    target_compile_definitions(mbedcrypto PUBLIC OC_DEBUG)
endif()

if(OC_CLOUD_ENABLED)
    target_compile_definitions(iotivity-common INTERFACE OC_CLOUD)
endif()

if(OC_IDD_API_ENABLED)
    target_compile_definitions(iotivity-common INTERFACE OC_IDD_API)
endif()

if(OC_TCP_ENABLED)
    target_compile_definitions(iotivity-common INTERFACE OC_TCP)
endif()

if(OC_DISCOVERY_RESOURCE_OBSERVABLE_ENABLED)
    target_compile_definitions(iotivity-common INTERFACE OC_DISCOVERY_RESOURCE_OBSERVABLE)
endif()

if(OC_REPRESENTATION_REALLOC_ENCODING_ENABLED)
    target_compile_definitions(iotivity-common INTERFACE OC_REP_ENCODING_REALLOC)
endif()

# Client and server versions of Iotivity
add_library(iotivity-client)
target_compile_definitions(iotivity-client PUBLIC OC_CLIENT)
target_link_libraries(iotivity-client PRIVATE
    iotivity-coap
    iotivity-api
)
target_link_libraries(iotivity-client PUBLIC iotivity-common)

add_library(iotivity-server)
target_compile_definitions(iotivity-server PUBLIC OC_SERVER)
target_link_libraries(iotivity-server PRIVATE
    iotivity-coap
    iotivity-api
)
target_link_libraries(iotivity-server PUBLIC iotivity-common)

add_library(iotivity-server-client)
target_compile_definitions(iotivity-server-client PUBLIC OC_SERVER OC_CLIENT)
target_link_libraries(iotivity-server-client PRIVATE
    iotivity-coap
    iotivity-api
)
target_link_libraries(iotivity-server-client PUBLIC iotivity-common)


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
