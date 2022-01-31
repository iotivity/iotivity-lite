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
set(PRIVATE_COMPILER_DEFS "")
set(PUBLIC_COMPILER_DEFS "")
if(OC_DYNAMIC_ALLOCATION_ENABLED)
    list(APPEND PUBLIC_COMPILER_DEFS "OC_DYNAMIC_ALLOCATION")
endif()

if(OC_SECURITY_ENABLED)
    list(APPEND PUBLIC_COMPILER_DEFS "OC_SECURITY")
endif()

if(OC_PKI_ENABLED)
    list(APPEND PUBLIC_COMPILER_DEFS "OC_PKI")
endif()

if(OC_DEBUG_ENABLED)
    list(APPEND PRIVATE_COMPILER_DEFS "OC_DEBUG")
endif()

if(OC_CLOUD_ENABLED)
    list(APPEND PUBLIC_COMPILER_DEFS "OC_CLOUD")
    set(OC_TCP_ENABLED ON)
    set(OC_IPV4_ENABLED ON)
endif()

if(OC_IDD_API_ENABLED)
    list(APPEND PUBLIC_COMPILER_DEFS "OC_IDD_API")
endif()

if(OC_TCP_ENABLED)
    list(APPEND PUBLIC_COMPILER_DEFS "OC_TCP")
endif()

if(OC_DISCOVERY_RESOURCE_OBSERVABLE_ENABLED)
    list(APPEND PRIVATE_COMPILER_DEFS "OC_DISCOVERY_RESOURCE_OBSERVABLE")
endif()

if(OC_REPRESENTATION_REALLOC_ENCODING_ENABLED)
    list(APPEND PRIVATE_COMPILER_DEFS "OC_REP_ENCODING_REALLOC")
endif()

if(OC_COLLECTIONS_IF_CREATE_ENABLED)
    list(APPEND PUBLIC_COMPILER_DEFS "OC_COLLECTIONS_IF_CREATE")
endif()

if(OC_MNT_ENABLED)
    list(APPEND PUBLIC_COMPILER_DEFS "OC_MNT")
endif()

if(OC_SOFTWARE_UPDATE_ENABLED)
    list(APPEND PUBLIC_COMPILER_DEFS "OC_SOFTWARE_UPDATE")
endif()

if(OC_WKCORE_ENABLED)
    list(APPEND PUBLIC_COMPILER_DEFS "OC_WKCORE")
endif()

if(OC_OSCORE_ENABLED)
    list(APPEND PUBLIC_COMPILER_DEFS "OC_OSCORE")
endif()

if(OC_IPV4_ENABLED)
    list(APPEND PUBLIC_COMPILER_DEFS "OC_IPV4")
endif()

if(OC_DNS_LOOKUP_IPV6_ENABLED)
    list(APPEND PRIVATE_COMPILER_DEFS "OC_DNS_LOOKUP_IPV6")
endif()

######## Gather source files ########
file(GLOB SRC_COMMON
    ${PROJECT_SOURCE_DIR}/api/c-timestamp/timestamp_format.c
    ${PROJECT_SOURCE_DIR}/api/c-timestamp/timestamp_valid.c
    ${PROJECT_SOURCE_DIR}/api/c-timestamp/timestamp_parse.c
    ${PROJECT_SOURCE_DIR}/util/*.c
)

if(OC_PKI_ENABLED)
    list(APPEND SRC_COMMON
        ${PROJECT_SOURCE_DIR}/api/c-timestamp/timestamp_tm.c
    )
endif()

file(GLOB SRC_SERVER
    ${PROJECT_SOURCE_DIR}/messaging/coap/*.c
    ${PROJECT_SOURCE_DIR}/api/*.c
)

file(GLOB SRC_CLIENT ${SRC_SERVER})

if(OC_SECURITY_ENABLED)
    file(GLOB SRC_SECURITY
        ${PROJECT_SOURCE_DIR}/security/oc_*.c
    )
    list(REMOVE_ITEM SRC_SECURITY
        ${PROJECT_SOURCE_DIR}/security/oc_obt*.c
    )
    list(APPEND SRC_SERVER ${SRC_SECURITY})
    list(APPEND SRC_CLIENT ${SRC_SECURITY})
    if(OC_DYNAMIC_ALLOCATION_ENABLED)
        file(GLOB SRC_OBT
            ${PROJECT_SOURCE_DIR}/security/oc_obt*.c
            )
        list(APPEND SRC_CLIENT ${SRC_OBT})
    endif()
endif()

if(OC_CLOUD_ENABLED)
    file(GLOB SRC_CLOUD api/cloud/*.c)
    set(CLOUD_INCLUDE_DIRS api/cloud)
endif()

######## Define link dependencies ########
set(PUBLIC_LINK_LIBS "")
set(PRIVATE_LINK_LIBS "")
if(MSVC)
    list(APPEND PRIVATE_LINK_LIBS iphlpapi.lib psapi.lib ws2_32.lib)
elseif(WIN32)
    list(APPEND PRIVATE_LINK_LIBS iphlpapi psapi wsock32 ws2_32)
else()
    find_package(Threads REQUIRED)
    list(APPEND PRIVATE_LINK_LIBS Threads::Threads)
endif()

if(OC_SECURITY_ENABLED)
    list(APPEND PUBLIC_LINK_LIBS mbedtls mbedcrypto mbedx509)
endif()

######## Object libraries ########
include(port/CMakeLists.txt)
include(deps/CMakeLists.txt)

get_target_property(PORT_DIR iotivity-port INCLUDE_DIRECTORIES)
get_target_property(MBEDTLS_DIR mbedtls INCLUDE_DIRECTORIES)

add_library(common-obj OBJECT ${SRC_COMMON})
target_compile_definitions(common-obj PRIVATE ${PRIVATE_COMPILER_DEFS} PUBLIC ${PUBLIC_COMPILER_DEFS})
target_include_directories(common-obj PRIVATE ${PROJECT_SOURCE_DIR} ${PROJECT_SOURCE_DIR}/include ${PORT_DIR})

add_library(client-obj OBJECT ${SRC_CLIENT})
target_compile_definitions(client-obj PRIVATE ${PRIVATE_COMPILER_DEFS} PUBLIC ${PUBLIC_COMPILER_DEFS} "OC_CLIENT")
target_include_directories(client-obj PRIVATE ${PROJECT_SOURCE_DIR} ${PROJECT_SOURCE_DIR}/include ${MBEDTLS_DIR} ${PORT_DIR})

add_library(server-obj OBJECT ${SRC_SERVER})
target_compile_definitions(server-obj PRIVATE ${PRIVATE_COMPILER_DEFS} PUBLIC ${PUBLIC_COMPILER_DEFS} "OC_SERVER")
target_include_directories(server-obj PRIVATE ${PROJECT_SOURCE_DIR} ${PROJECT_SOURCE_DIR}/include ${MBEDTLS_DIR} ${PORT_DIR})

add_library(client-server-obj OBJECT ${SRC_CLIENT})
target_compile_definitions(client-server-obj PRIVATE ${PRIVATE_COMPILER_DEFS} PUBLIC ${PUBLIC_COMPILER_DEFS} "OC_CLIENT" "OC_SERVER")
target_include_directories(client-server-obj PRIVATE ${PROJECT_SOURCE_DIR} ${PROJECT_SOURCE_DIR}/include ${MBEDTLS_DIR} ${PORT_DIR})

if(OC_CLOUD_ENABLED)
    add_library(cloud-obj OBJECT ${SRC_CLOUD})
    target_compile_definitions(cloud-obj PRIVATE ${PRIVATE_COMPILER_DEFS} PUBLIC ${PUBLIC_COMPILER_DEFS})
    target_include_directories(cloud-obj PRIVATE ${PROJECT_SOURCE_DIR} ${PROJECT_SOURCE_DIR}/include ${MBEDTLS_DIR} ${PORT_DIR})
endif()

######## Compose static and shared libraries ########
# Client
add_library(client-static STATIC
    $<TARGET_OBJECTS:common-obj>
    $<TARGET_OBJECTS:iotivity-port>
    $<TARGET_OBJECTS:tinycbor-master>
    $<TARGET_OBJECTS:client-obj>
)
set_target_properties(client-static PROPERTIES
    OUTPUT_NAME "iotivity-lite-client"
    VERSION ${PROJECT_VERSION}
)

add_library(client-shared SHARED
    $<TARGET_OBJECTS:common-obj>
    $<TARGET_OBJECTS:iotivity-port>
    $<TARGET_OBJECTS:tinycbor-master>
    $<TARGET_OBJECTS:client-obj>
)
target_link_libraries(client-shared PUBLIC ${PUBLIC_LINK_LIBS} PRIVATE ${PRIVATE_LINK_LIBS})
set_target_properties(client-shared PROPERTIES
    OUTPUT_NAME "iotivity-lite-client"
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
)

# Server
set(server-lib-obj
    $<TARGET_OBJECTS:common-obj>
    $<TARGET_OBJECTS:iotivity-port>
    $<TARGET_OBJECTS:tinycbor-master>
    $<TARGET_OBJECTS:server-obj>
)
if(OC_CLOUD_ENABLED)
    list(APPEND server-lib-obj $<TARGET_OBJECTS:cloud-obj>)
endif()

add_library(server-static STATIC ${server-lib-obj})
set_target_properties(server-static PROPERTIES
    OUTPUT_NAME "iotivity-lite-server"
    VERSION ${PROJECT_VERSION}
)

add_library(server-shared SHARED ${server-lib-obj})
target_link_libraries(server-shared PUBLIC ${PUBLIC_LINK_LIBS} PRIVATE ${PRIVATE_LINK_LIBS})
set_target_properties(server-shared PROPERTIES
    OUTPUT_NAME "iotivity-lite-server"
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
)

# Client-Server
set(client-server-lib-obj
    $<TARGET_OBJECTS:common-obj>
    $<TARGET_OBJECTS:iotivity-port>
    $<TARGET_OBJECTS:tinycbor-master>
    $<TARGET_OBJECTS:client-server-obj>
)
if(OC_CLOUD_ENABLED)
    list(APPEND client-server-lib-obj $<TARGET_OBJECTS:cloud-obj>)
endif()
add_library(client-server-static STATIC ${client-server-lib-obj})
set_target_properties(client-server-static PROPERTIES
    OUTPUT_NAME "iotivity-lite-client-server"
    VERSION ${PROJECT_VERSION}
)

add_library(client-server-shared SHARED ${client-server-lib-obj})
target_link_libraries(client-server-shared PUBLIC ${PUBLIC_LINK_LIBS} PRIVATE ${PRIVATE_LINK_LIBS})
set_target_properties(client-server-shared PROPERTIES
    OUTPUT_NAME "iotivity-lite-client-server"
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
)

######## Installation ########
# Libraries
install(TARGETS
    client-static client-shared
    server-static server-shared
    client-server-static client-server-shared
    EXPORT iotivity-lite_TARGETS
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR} COMPONENT bin
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR} COMPONENT lib
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR} COMPONENT dev
)

# Header files
install(DIRECTORY include/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/iotivity-lite COMPONENT dev
    FILES_MATCHING PATTERN "*.h"
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
