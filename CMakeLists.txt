cmake_minimum_required (VERSION 3.10)
project(iotivity-lite VERSION 2.2.5)

include(GNUInstallDirs) # Installation directories for `install` command and pkgconfig file

######## Build configuration options ########
set(BUILD_EXAMPLE_APPLICATIONS ON CACHE BOOL "Build example applications.")
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

set(OC_ASAN_ENABLED OFF CACHE BOOL "Enable address sanitizer build.")
set(OC_LSAN_ENABLED OFF CACHE BOOL "Enable leak sanitizer build.")
set(OC_TSAN_ENABLED OFF CACHE BOOL "Enable thread sanitizer build.")
set(OC_MSAN_ENABLED OFF CACHE BOOL "Enable memory sanitizer build. (clang on Linux only)")
set(OC_UBSAN_ENABLED OFF CACHE BOOL "Enable undefined behaviour sanitizer build.")

if(UNIX)
    if(OC_ASAN_ENABLED)
        message(STATUS "Address sanitizer enabled")
        add_compile_options(${CMAKE_C_FLAGS_DEBUG} -fsanitize=address -fno-omit-frame-pointer)
        add_link_options(-fsanitize=address)
    endif()

    if(OC_LSAN_ENABLED)
        message(STATUS "Leak sanitizer enabled")
        add_compile_options(${CMAKE_C_FLAGS_DEBUG} -fsanitize=leak -fno-omit-frame-pointer)
        add_link_options(-fsanitize=leak)
    endif()

    if(OC_TSAN_ENABLED)
        message(STATUS "Thread sanitizer enabled")
        add_compile_options(${CMAKE_C_FLAGS_DEBUG} -fsanitize=thread -fno-omit-frame-pointer)
        add_link_options(-fsanitize=thread)
    endif()

    if(OC_UBSAN_ENABLED)
        message(STATUS "Undefined behaviour sanitizer enabled")
        add_compile_options(${CMAKE_C_FLAGS_DEBUG} -fsanitize=undefined -fno-omit-frame-pointer)
        add_link_options(-fsanitize=undefined)
    endif()

    if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
        # using clang
        if(OC_MSAN_ENABLED)
            message(STATUS "Memory sanitizer enabled")
            add_compile_options(${CMAKE_C_FLAGS_DEBUG} -fsanitize=memory -fno-omit-frame-pointer)
            add_link_options(-fsanitize=memory)
        endif()
    elseif (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        # using GCC
    endif()

    if(OC_ASAN_ENABLED OR OC_LSAN_ENABLED OR OC_TSAN_ENABLED OR OC_UBSAN_ENABLED OR OC_MSAN_ENABLED)
        # to get good stacktraces don't use -O2 or -O3 for sanitized optimized build
        set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -O1")
        set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O1")
        set(CMAKE_C_FLAGS_RELWITHDEBINFO "${CMAKE_C_FLAGS_RELWITHDEBINFO} -O1")
        set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "${CMAKE_CXX_FLAGS_RELWITHDEBINFO} -O1")
    endif()
endif()

set(OC_CLANG_TIDY_ENABLED OFF CACHE BOOL "Enable clang-tidy analysis during compilation.")

include(tools/clang-tidy.cmake)

######## Define compiler flags ########
set(PRIVATE_COMPILE_DEFINITIONS "")
set(PUBLIC_COMPILE_DEFINITIONS "")
set(PRIVATE_COMPILE_OPTIONS "")
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

######## Target dependencies ########
set(TARGET_DEPENDENCIES "")

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
elseif(DEFINED ZEPHYR_BASE)
    # Set the Zephyr CMake task zephyr_interface as dependency.
    # Zephyr generates some platform headers in that CMake task which needs to be completed
    # before iotivity-lite compilation can start or the headers can not be found.
    list(APPEND TARGET_DEPENDENCIES zephyr_interface)

    # Set the Zephyr include directories globally.
    # Taken from zephyr/cmake/extensions.cmake: zephyr_get_include_directories_for_lang(C includes)
    get_property(zephyr_include_dirs TARGET zephyr_interface PROPERTY INTERFACE_INCLUDE_DIRECTORIES)
    get_property(posix_subsys_include_dirs TARGET posix_subsys PROPERTY INTERFACE_INCLUDE_DIRECTORIES)
    # The Zephyr IP subsystem provides helper functions for IPv6 multicast functions in the
    # subsys/net/ip/ipv6.h header file. But this header file is not provided by any Zephyr CMake target.
    set(net_ip_subsys_include_dirs ${ZEPHYR_BASE}/subsys/net/ip)
    include_directories(${zephyr_include_dirs} ${posix_subsys_include_dirs} ${net_ip_subsys_include_dirs})

    # Add Zephyr compile definitions.
    # Taken from zephyr/cmake/extensions.cmake: zephyr_get_compile_definitions_for_lang(C definitions)
    get_property(zephyr_compile_defs TARGET zephyr_interface PROPERTY INTERFACE_COMPILE_DEFINITIONS)
    list(APPEND PRIVATE_COMPILE_DEFINITIONS ${zephyr_compile_defs})
    list(APPEND PRIVATE_COMPILE_DEFINITIONS CBOR_NO_FLOATING_POINT)

    # Add Zephyr compile options.
    # Taken from zephyr/cmake/extensions.cmake: zephyr_get_compile_options_for_lang(C options)
    get_property(zephyr_compile_opts TARGET zephyr_interface PROPERTY INTERFACE_COMPILE_OPTIONS)
    list(APPEND PRIVATE_COMPILE_OPTIONS ${zephyr_compile_opts})

    file(GLOB PORT_SRC port/zephyr/src/[a-r]*.c)
    if(CONFIG_FILE_SYSTEM)
        message(STATUS "Using file system storage.")
        list(APPEND PORT_SRC port/zephyr/src/storage_fs.c)
    elseif(CONFIG_FLASH)
        message(STATUS "Using raw flash storage.")
        list(APPEND PORT_SRC port/zephyr/src/storage_flash.c)
    else()
        message(FATAL_ERROR "Cannot determine the storage technology to use!")
    endif()
    set(PORT_INCLUDE_DIR ${PROJECT_SOURCE_DIR}/port/zephyr/src)
else()
    message(FATAL_ERROR "Cannot determine the port to use!")
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
target_compile_options(common-obj PRIVATE ${PRIVATE_COMPILE_OPTIONS})
target_include_directories(common-obj PRIVATE ${PROJECT_SOURCE_DIR} ${PROJECT_SOURCE_DIR}/include ${PROJECT_SOURCE_DIR}/port ${PORT_INCLUDE_DIR})
if(TARGET_DEPENDENCIES)
    add_dependencies(common-obj ${TARGET_DEPENDENCIES})
endif()

add_library(client-obj OBJECT ${CLIENT_SRC})
target_compile_definitions(client-obj PRIVATE ${PRIVATE_COMPILE_DEFINITIONS} PUBLIC ${PUBLIC_COMPILE_DEFINITIONS} "OC_CLIENT")
target_compile_options(client-obj PRIVATE ${PRIVATE_COMPILE_OPTIONS})
target_include_directories(client-obj PRIVATE ${PROJECT_SOURCE_DIR} ${PROJECT_SOURCE_DIR}/include ${PROJECT_SOURCE_DIR}/port ${PORT_INCLUDE_DIR})
if(OC_SECURITY_ENABLED)
    target_include_directories(client-obj PRIVATE ${MBEDTLS_INCLUDE_DIRS})
endif()
if(TARGET_DEPENDENCIES)
    add_dependencies(client-obj ${TARGET_DEPENDENCIES})
endif()

add_library(server-obj OBJECT ${SERVER_SRC})
target_compile_definitions(server-obj PRIVATE ${PRIVATE_COMPILE_DEFINITIONS} PUBLIC ${PUBLIC_COMPILE_DEFINITIONS} "OC_SERVER")
target_compile_options(server-obj PRIVATE ${PRIVATE_COMPILE_OPTIONS})
target_include_directories(server-obj PRIVATE ${PROJECT_SOURCE_DIR} ${PROJECT_SOURCE_DIR}/include ${PROJECT_SOURCE_DIR}/port ${PORT_INCLUDE_DIR})
if(OC_SECURITY_ENABLED)
    target_include_directories(server-obj PRIVATE ${MBEDTLS_INCLUDE_DIRS})
endif()
if(TARGET_DEPENDENCIES)
    add_dependencies(server-obj ${TARGET_DEPENDENCIES})
endif()

add_library(client-server-obj OBJECT ${CLIENT_SRC})
target_compile_definitions(client-server-obj PRIVATE ${PRIVATE_COMPILE_DEFINITIONS} PUBLIC ${PUBLIC_COMPILE_DEFINITIONS} "OC_CLIENT" "OC_SERVER")
target_compile_options(client-server-obj PRIVATE ${PRIVATE_COMPILE_OPTIONS})
target_include_directories(client-server-obj PRIVATE ${PROJECT_SOURCE_DIR} ${PROJECT_SOURCE_DIR}/include ${PROJECT_SOURCE_DIR}/port ${PORT_INCLUDE_DIR})
if(OC_SECURITY_ENABLED)
    target_include_directories(client-server-obj PRIVATE ${MBEDTLS_INCLUDE_DIRS})
endif()
if(TARGET_DEPENDENCIES)
    add_dependencies(client-server-obj ${TARGET_DEPENDENCIES})
endif()

if(OC_CLOUD_ENABLED)
    add_library(cloud-obj OBJECT ${CLOUD_SRC})
    target_compile_definitions(cloud-obj PRIVATE ${PRIVATE_COMPILE_DEFINITIONS} PUBLIC ${PUBLIC_COMPILE_DEFINITIONS})
    target_compile_options(cloud-obj PRIVATE ${PRIVATE_COMPILE_OPTIONS})
    target_include_directories(cloud-obj PRIVATE ${PROJECT_SOURCE_DIR} ${PROJECT_SOURCE_DIR}/include ${PROJECT_SOURCE_DIR}/port ${PORT_INCLUDE_DIR})
    if(OC_SECURITY_ENABLED)
        target_include_directories(cloud-obj PRIVATE ${MBEDTLS_INCLUDE_DIRS})
    endif()
endif()

add_library(python-obj OBJECT ${PYTHON_SRC})
target_compile_definitions(python-obj PRIVATE ${PRIVATE_COMPILE_DEFINITIONS} OC_LIBRARY_EXPORT PUBLIC ${PUBLIC_COMPILE_DEFINITIONS} "OC_LIBRARY" "OC_CLIENT")
target_compile_options(python-obj PRIVATE ${PRIVATE_COMPILE_OPTIONS})
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

if(TARGET_SUPPORTS_SHARED_LIBS AND NOT MSVC)
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

if(TARGET_SUPPORTS_SHARED_LIBS AND NOT MSVC)
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

if(TARGET_SUPPORTS_SHARED_LIBS AND NOT MSVC)
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
    if(CMAKE_COMPILER_IS_GNUCXX AND NOT (OC_ASAN_ENABLED OR OC_LSAN_ENABLED OR OC_TSAN_ENABLED OR OC_UBSAN_ENABLED))
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
if(NOT TARGET_SUPPORTS_SHARED_LIBS OR MSVC)
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

######## Sub-projects ########
if(UNIX)
    add_subdirectory(tests)
endif()
if(BUILD_EXAMPLE_APPLICATIONS)
    add_subdirectory(onboarding_tool)
    add_subdirectory(apps)
endif()
