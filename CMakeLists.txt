cmake_minimum_required(VERSION 3.13)
project(iotivity-lite)

# Patch mbedtls
include(mbedtls-patch.cmake)

# Do not build anything except for the library
option(ENABLE_PROGRAMS "Build mbed TLS programs." OFF)
option(ENABLE_TESTING "Build mbed TLS tests." OFF)
# Configurable dynamic memory use
set(OC_DYNAMIC_ALLOCATION_ENABLED ON CACHE BOOL "Enable dynamic memory allocation within the OCF stack and MBedtls.")

# If an mbedtls platform layer is defined, add it to the mbedtls list of libs
if(TARGET mbedtls-plat)
    set(libs ${libs} mbedtls-plat)
endif()

add_subdirectory(${PROJECT_SOURCE_DIR}/deps/mbedtls)

target_include_directories(mbedcrypto PUBLIC
    ${PROJECT_SOURCE_DIR}/port/linux
    ${PROJECT_SOURCE_DIR}
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/deps/mbedtls/include
)

if(TARGET mbedcrypto-plat)
	target_link_libraries(mbedcrypto PUBLIC mbedcrypto-plat)
endif()

if(OC_DYNAMIC_ALLOCATION_ENABLED)
    target_compile_definitions(mbedcrypto PUBLIC OC_DYNAMIC_ALLOCATION)
endif()


add_library(iotivity-port INTERFACE)

target_sources(iotivity-port INTERFACE
    ${PROJECT_SOURCE_DIR}/port/linux/abort.c
    ${PROJECT_SOURCE_DIR}/port/linux/clock.c
    ${PROJECT_SOURCE_DIR}/port/linux/ipadapter.c
    ${PROJECT_SOURCE_DIR}/port/linux/random.c
    ${PROJECT_SOURCE_DIR}/port/linux/storage.c
    ${PROJECT_SOURCE_DIR}/port/linux/tcpadapter.c
)

target_include_directories(iotivity-port INTERFACE
    ${PROJECT_SOURCE_DIR}/port/linux
)

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

# Client and server versions of Iotivity
add_library(iotivity-client INTERFACE)

target_link_libraries(iotivity-client INTERFACE
    iotivity-coap
    iotivity-common
    iotivity-api
)

target_compile_definitions(iotivity-client INTERFACE OC_CLIENT)

add_library(iotivity-server INTERFACE)

target_link_libraries(iotivity-server INTERFACE
    iotivity-coap
    iotivity-common
    iotivity-api
)

target_compile_definitions(iotivity-server INTERFACE OC_SERVER)

# Configurable debugging
set(OC_DEBUG_ENABLED OFF CACHE BOOL "Enable debug messages from the Iotivity stack.")

if(OC_DEBUG_ENABLED)
    target_compile_definitions(iotivity-server INTERFACE OC_DEBUG)
    target_compile_definitions(iotivity-client INTERFACE OC_DEBUG)
    target_compile_definitions(iotivity-common INTERFACE OC_DEBUG)
endif()

# TODO remove cascoda from this var
if(CASCODA_BUILD_OCF_PKI)
    target_compile_definitions(mbedcrypto PUBLIC OC_PKI)
endif()

add_library(iotivity-secure-server)
target_link_libraries(iotivity-secure-server PRIVATE iotivity-server)
target_compile_definitions(iotivity-secure-server PUBLIC OC_SERVER OC_SECURITY)