cmake_minimum_required(VERSION 3.10)
project(iotivity-lite VERSION 2.2.5.10)

include(GNUInstallDirs) # Installation directories for `install` command and pkgconfig file

######## Helper variables ########
set(OC_COMPILER_IS_GCC ${CMAKE_COMPILER_IS_GNUCXX} CACHE BOOL "Compiler is gcc" FORCE)

set(OC_COMPILER_IS_CLANG OFF CACHE BOOL "Compiler is clang." FORCE)
if(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
	set(OC_COMPILER_IS_CLANG ON CACHE BOOL "Compiler is clang." FORCE)
endif()

set(OC_COVERAGE_ENABLED OFF CACHE BOOL "Gather code coverage")
if(BUILD_TESTING AND UNIX AND (OC_COMPILER_IS_GCC OR OC_COMPILER_IS_CLANG))
    if(NOT(OC_ASAN_ENABLED OR OC_LSAN_ENABLED OR OC_TSAN_ENABLED OR OC_UBSAN_ENABLED))
        set(OC_COVERAGE_ENABLED ON CACHE BOOL "Gather code coverage" FORCE)
    endif()
endif()

######## Build configuration options ########
set(BUILD_EXAMPLE_APPLICATIONS ON CACHE BOOL "Build example applications.")
set(BUILD_MBEDTLS ON CACHE BOOL "Build Mbed TLS library. When set to OFF, the Mbed TLS library with the OCF patches has to be provided.")
set(OC_INSTALL_MBEDTLS ON CACHE BOOL "Include Mbed TLS in installation")
set(BUILD_TINYCBOR ON CACHE BOOL "Build TinyCBOR library. When set to OFF, the TinyCBOR library has to be provided.")
set(OC_INSTALL_TINYCBOR ON CACHE BOOL "Include TinyCBOR in installation")

set(OC_DYNAMIC_ALLOCATION_ENABLED ON CACHE BOOL "Enable dynamic memory allocation within the OCF stack and Mbed TLS.")
set(OC_SECURITY_ENABLED ON CACHE BOOL "Enable security.")
if (OC_SECURITY_ENABLED)
    set(OC_PKI_ENABLED ON CACHE BOOL "Enable PKI security.")
else()
    # Force PKI security to be disabled if security is disabled
    set(OC_PKI_ENABLED OFF CACHE BOOL "Disable PKI security (force)" FORCE)
endif()
set(OC_CLOUD_ENABLED OFF CACHE BOOL "Enable cloud communications.")
set(OC_DEBUG_ENABLED OFF CACHE BOOL "Enable debug messages.")
set(OC_INTROSPECTION_ENABLED ON CACHE BOOL "Enable the introspection resource.")
set(OC_IDD_API_ENABLED ON CACHE BOOL "Enable the Introspection Device Data API.")
set(OC_TCP_ENABLED OFF CACHE BOOL "Enable OCF communications over TCP. Necessary for Cloud communications.")
set(OC_DISCOVERY_RESOURCE_OBSERVABLE_ENABLED OFF CACHE BOOL "Enable observation over oic/res resource.")
set(OC_REPRESENTATION_REALLOC_ENCODING_ENABLED OFF CACHE BOOL "Enable realloc during encoding the representation.")
set(OC_COLLECTIONS_IF_CREATE_ENABLED OFF CACHE BOOL "Enable RT factory for collections.")
set(OC_MNT_ENABLED OFF CACHE BOOL "Enable maintenance resource.")
set(OC_SOFTWARE_UPDATE_ENABLED OFF CACHE BOOL "Enable software update resource.")
set(OC_WKCORE_ENABLED OFF CACHE BOOL "Enable well-known core resource.")
set(OC_OSCORE_ENABLED ON CACHE BOOL "Enable oscore support.")
set(OC_IPV4_ENABLED OFF CACHE BOOL "Enable IPv4 support.")
set(OC_DNS_LOOKUP_IPV6_ENABLED OFF CACHE BOOL "Enable IPv6 DNS lookup.")
set(OC_PUSH_ENABLED OFF CACHE BOOL "Enable Push Notification.")
set(OC_PUSHDEBUG_ENABLED OFF CACHE BOOL "Enable debug messages for Push Notification.")
set(OC_RESOURCE_ACCESS_IN_RFOTM_ENABLED OFF CACHE BOOL "Enable resource access in RFOTM.")
set(OC_MEMORY_TRACE_ENABLED OFF CACHE BOOL "Enable memory tracing.")
if (OC_DEBUG_ENABLED)
    set(OC_LOG_MAXIMUM_LOG_LEVEL "TRACE" CACHE STRING "Maximum supported log level in compile time.")
else()
    set(OC_LOG_MAXIMUM_LOG_LEVEL "DISABLED" CACHE STRING "Maximum supported log level in compile time.")
endif()
set(OC_INOUT_BUFFER_SIZE "" CACHE STRING "Custom static buffer size for network messages.")
set(OC_INOUT_BUFFER_POOL "" CACHE STRING "Custom static pool size of network messages.")
set(OC_APP_DATA_BUFFER_SIZE "" CACHE STRING "Custom static buffer size for application messages.")
set(OC_APP_DATA_BUFFER_POOL "" CACHE STRING "Custom static size of application messages.")
set(OC_VERSION_1_1_0_ENABLED OFF CACHE BOOL "Enable OCF version 1.1")
set(OC_ETAG_ENABLED OFF CACHE BOOL "Enable Entity Tag (ETag) support.")
set(OC_JSON_ENCODER_ENABLED OFF CACHE BOOL "Enable JSON encoder/decoder support.")
set(PLGD_DEV_TIME_ENABLED OFF CACHE BOOL "Enable plgd time feature.")

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

set(OC_ASAN_ENABLED OFF CACHE BOOL "Enable address sanitizer build.")
set(OC_LSAN_ENABLED OFF CACHE BOOL "Enable leak sanitizer build.")
set(OC_TSAN_ENABLED OFF CACHE BOOL "Enable thread sanitizer build.")
set(OC_MSAN_ENABLED OFF CACHE BOOL "Enable memory sanitizer build. (clang on Linux only)")
set(OC_UBSAN_ENABLED OFF CACHE BOOL "Enable undefined behaviour sanitizer build.")

if(OC_CLOUD_ENABLED AND OC_SECURITY_ENABLED AND NOT OC_PKI_ENABLED)
    message(FATAL_ERROR "Cannot enable cloud communications without PKI security")
endif()

if(UNIX)
    if(OC_ASAN_ENABLED)
        message(STATUS "Address sanitizer enabled")
        add_compile_options(${CMAKE_C_FLAGS_DEBUG} -fsanitize=address -fno-omit-frame-pointer)
        add_link_options(-fsanitize=address)
        set(OC_ASAN_OPTIONS "debug=true:atexit=true:check_initialization_order=true:detect_stack_use_after_return=true:alloc_dealloc_mismatch=true:detect_invalid_pointer_pairs=2:strict_string_checks=true")
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
        set(OC_TSAN_OPTIONS "halt_on_error=1:abort_on_error=true")
    endif()

    if(OC_UBSAN_ENABLED)
        message(STATUS "Undefined behaviour sanitizer enabled")
        if(OC_COMPILER_IS_CLANG)
            # -fno-sanitize-recover=undefined,local-bounds,nullability
            add_compile_options(${CMAKE_C_FLAGS_DEBUG} -fsanitize=undefined,local-bounds,nullability -fno-omit-frame-pointer)
        else()
            # -fno-sanitize-recover=undefined
            add_compile_options(${CMAKE_C_FLAGS_DEBUG} -fsanitize=undefined -fno-omit-frame-pointer)
        endif()
        add_link_options(-fsanitize=undefined)
        # halt_on_error=1
        set(OC_UBSAN_OPTIONS "print_stacktrace=1")
    endif()

    if(OC_COMPILER_IS_CLANG)
        # using clang
        if(OC_MSAN_ENABLED)
            message(STATUS "Memory sanitizer enabled")
            add_compile_options(${CMAKE_C_FLAGS_DEBUG} -fsanitize=memory -fno-omit-frame-pointer)
            add_link_options(-fsanitize=memory)
        endif()
    elseif(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
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

# Compiler and linker flags
if(OC_COMPILER_IS_GCC)
	set(OC_COMPILE_OPTIONS_RELEASE -fdata-sections -ffunction-sections)
	# -Wl,--as-needed       = Only link libraries that export symbols used by the binary
	# -Wl,--gc-sections     = Remove unused code resulting from -fdata-sections and -function-sections
	# -s                    = Strip
	set(OC_LINK_OPTIONS_RELEASE -Wl,--as-needed -Wl,--gc-sections -s)
endif()

if(OC_COMPILER_IS_CLANG)
	# -Wl,-dead_strip       = Remove unused code
    # -s                    = Strip
	set(OC_LINK_OPTIONS_RELEASE -Wl,-dead_strip -s)
endif()

set(OC_CLANG_TIDY_ENABLED OFF CACHE BOOL "Enable clang-tidy analysis during compilation.")

include(tools/clang-tidy.cmake)

include(CheckCCompilerFlag)
include(CheckCXXCompilerFlag)
# function oc_add_compile_options([GLOBAL] [IX_CXX] FLAGS [flags...])
#
# Arguments:
#   GLOBAL   (option) flags are added as global compilation options
#   FLAGS    list of flags to check and add for both C and C++
#   CFLAGS   list of flags to check and add for C
#   CXXFLAGS list of flags to check and add for C++
#
# Side-effect: C_COMPILER_SUPPORTS_${flag_name} / CXX_COMPILER_SUPPORTS_${flag_name}
# is created and set to ON/OFF based on the result of the check. This variable
# can be used in the context of the caller.
function(oc_add_compile_options)
    set(options GLOBAL)
    set(oneValueArgs)
    set(multiValueArgs CFLAGS CXXFLAGS FLAGS)
    cmake_parse_arguments(OC_ADD_COMPILE_OPTIONS "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})

    foreach(flag IN LISTS OC_ADD_COMPILE_OPTIONS_FLAGS OC_ADD_COMPILE_OPTIONS_CFLAGS)
        string(REPLACE "-" "_" flag_name ${flag})
        string(REPLACE "=" "_" flag_name ${flag_name})
        string(TOUPPER ${flag_name} flag_name)
        set(flag_name "C_COMPILER_SUPPORTS${flag_name}")
        unset(${flag_name})
        check_c_compiler_flag(${flag} ${flag_name})
        if((OC_ADD_COMPILE_OPTIONS_GLOBAL) AND (${${flag_name}}))
            add_compile_options($<$<COMPILE_LANGUAGE:C>:${flag}>)
        endif()
        set(${flag_name} ${${flag_name}} PARENT_SCOPE)
    endforeach()

    foreach(flag IN LISTS OC_ADD_COMPILE_OPTIONS_FLAGS OC_ADD_COMPILE_OPTIONS_CXXFLAGS)
        string(REPLACE "-" "_" flag_name ${flag})
        string(REPLACE "=" "_" flag_name ${flag_name})
        string(TOUPPER ${flag_name} flag_name)
        set(flag_name "CXX_COMPILER_SUPPORTS${flag_name}")
        unset(${flag_name})
        check_cxx_compiler_flag(${flag} ${flag_name})
        if((OC_ADD_COMPILE_OPTIONS_GLOBAL) AND (${${flag_name}}))
            add_compile_options($<$<COMPILE_LANGUAGE:CXX>:${flag}>)
        endif()
        set(${flag_name} ${${flag_name}} PARENT_SCOPE)
    endforeach()
endfunction()

# Global compile options
set(PRIVATE_COMPILE_OPTIONS "")
set(MBEDTLS_COMPILE_OPTIONS "")
if(MSVC)
    # TODO: Enable and fix issues
    # list(APPEND PRIVATE_COMPILE_OPTIONS /WX)
elseif(OC_COMPILER_IS_GCC OR OC_COMPILER_IS_CLANG)
    oc_add_compile_options(GLOBAL
        FLAGS -Wall -Wextra -pedantic
            -Wwrite-strings -Wunused -Wunreachable-code -Wcast-align -Wpointer-arith -Wmissing-declarations
            -fno-common
        CFLAGS -Wmissing-prototypes -Wstrict-prototypes
    )

    if(NOT OC_CLANG_TIDY_ENABLED)
        oc_add_compile_options(GLOBAL
            CXXFLAGS -Wuseless-cast -Wno-error=useless-cast
        )
    endif()

    list(APPEND PRIVATE_COMPILE_OPTIONS -Werror)

    oc_add_compile_options(FLAGS -Wdocumentation)
    if(C_COMPILER_SUPPORTS_WDOCUMENTATION)
        list(APPEND PRIVATE_COMPILE_OPTIONS -Wdocumentation)
        list(APPEND MBEDTLS_COMPILE_OPTIONS -Wno-documentation)
    endif()

    # oc_add_compile_options(FLAGS -Wstack-usage=8192)
    # if(CXX_COMPILER_SUPPORTS_WSTACK_USAGE_8192)
    #     list(APPEND PRIVATE_COMPILE_OPTIONS -Wstack-usage=8192)
    # endif()

    # TODO: alignment warnings appear on some 32-bit compilers, keep those just
    # as warnings for now
    oc_add_compile_options(GLOBAL FLAGS -Wno-error=cast-align -Wno-error=deprecated-declarations
        -Wno-error=documentation)
endif()

# Release compile and linker options
add_compile_options("$<$<OR:$<CONFIG:Release>,$<CONFIG:RelWithDebInfo>,$<CONFIG:MinSizeRel>>:${OC_COMPILE_OPTIONS_RELEASE}>")
add_link_options("$<$<OR:$<CONFIG:Release>,$<CONFIG:RelWithDebInfo>,$<CONFIG:MinSizeRel>>:${OC_LINK_OPTIONS_RELEASE}>")

######## Define compiler flags ########
set(PRIVATE_COMPILE_DEFINITIONS "")
set(PUBLIC_COMPILE_DEFINITIONS "")
if(BUILD_MBEDTLS)
    set(MBEDTLS_COMPILE_DEFINITIONS "__OC_PLATFORM")
endif()

set(OC_LOG_MAXIMUM_LEVEL)
if(OC_LOG_MAXIMUM_LOG_LEVEL STREQUAL "DISABLED")
    set(OC_LOG_MAXIMUM_LEVEL -1)
    # list(APPEND PRIVATE_COMPILE_DEFINITIONS "OC_LOG_MAXIMUM_LEVEL=-1")
elseif(OC_LOG_MAXIMUM_LOG_LEVEL STREQUAL "ERROR")
    # list(APPEND PRIVATE_COMPILE_DEFINITIONS "OC_LOG_MAXIMUM_LEVEL=3")
    set(OC_LOG_MAXIMUM_LEVEL 3)
elseif(OC_LOG_MAXIMUM_LOG_LEVEL STREQUAL "WARNING")
    # list(APPEND PRIVATE_COMPILE_DEFINITIONS "OC_LOG_MAXIMUM_LEVEL=4")
    set(OC_LOG_MAXIMUM_LEVEL 4)
elseif(OC_LOG_MAXIMUM_LOG_LEVEL STREQUAL "NOTICE")
    # list(APPEND PRIVATE_COMPILE_DEFINITIONS "OC_LOG_MAXIMUM_LEVEL=5")
    set(OC_LOG_MAXIMUM_LEVEL 5)
elseif(OC_LOG_MAXIMUM_LOG_LEVEL STREQUAL "INFO")
    # list(APPEND PRIVATE_COMPILE_DEFINITIONS "OC_LOG_MAXIMUM_LEVEL=6")
    set(OC_LOG_MAXIMUM_LEVEL 6)
elseif(OC_LOG_MAXIMUM_LOG_LEVEL STREQUAL "DEBUG")
    # list(APPEND PRIVATE_COMPILE_DEFINITIONS "OC_LOG_MAXIMUM_LEVEL=7")
    set(OC_LOG_MAXIMUM_LEVEL 7)
elseif(OC_LOG_MAXIMUM_LOG_LEVEL STREQUAL "TRACE")
    # list(APPEND PRIVATE_COMPILE_DEFINITIONS "OC_LOG_MAXIMUM_LEVEL=8")
    set(OC_LOG_MAXIMUM_LEVEL 8)
else()
    message(FATAL_ERROR "Invalid OC_LOG_MAXIMUM_LOG_LEVEL: ${OC_LOG_MAXIMUM_LOG_LEVEL}")
endif()
# clang-tidy triggers bugprone-macro-parentheses if the value is not in ()
list(APPEND PRIVATE_COMPILE_DEFINITIONS "OC_LOG_MAXIMUM_LEVEL=(${OC_LOG_MAXIMUM_LEVEL})")
list(APPEND TEST_COMPILE_DEFINITIONS "OC_LOG_MAXIMUM_LEVEL=(${OC_LOG_MAXIMUM_LEVEL})")

if(OC_PUSH_ENABLED)
    list(APPEND PUBLIC_COMPILE_DEFINITIONS "OC_PUSH")
    if(OC_PUSHDEBUG_ENABLED)
        list(APPEND PRIVATE_COMPILE_DEFINITIONS "OC_PUSHDEBUG")
    endif()
    set(OC_DYNAMIC_ALLOCATION_ENABLED ON)
    set(OC_COLLECTIONS_IF_CREATE_ENABLED ON)
endif()
if(OC_RESOURCE_ACCESS_IN_RFOTM_ENABLED)
    if(NOT OC_SECURITY_ENABLED)
        message(FATAL_ERROR "Cannot enable resource access in RFOTM without security")
    endif()
    list(APPEND PUBLIC_COMPILE_DEFINITIONS "OC_RESOURCE_ACCESS_IN_RFOTM")
endif()
if(OC_DYNAMIC_ALLOCATION_ENABLED)
    list(APPEND PUBLIC_COMPILE_DEFINITIONS "OC_DYNAMIC_ALLOCATION")
    if(BUILD_MBEDTLS)
        list(APPEND MBEDTLS_COMPILE_DEFINITIONS "OC_DYNAMIC_ALLOCATION")
    endif()
endif()

if(OC_SECURITY_ENABLED)
    list(APPEND PUBLIC_COMPILE_DEFINITIONS "OC_SECURITY")
endif()

if(OC_PKI_ENABLED)
    list(APPEND PUBLIC_COMPILE_DEFINITIONS "OC_PKI")
    if(BUILD_MBEDTLS)
        list(APPEND MBEDTLS_COMPILE_DEFINITIONS "OC_PKI")
    endif()
endif()

if(OC_DEBUG_ENABLED)
    list(APPEND PRIVATE_COMPILE_DEFINITIONS "OC_DEBUG")
    if(BUILD_MBEDTLS)
        list(APPEND MBEDTLS_COMPILE_DEFINITIONS "OC_DEBUG")
    endif()
    list(APPEND TEST_COMPILE_DEFINITIONS "OC_DEBUG")
endif()

if(OC_CLOUD_ENABLED)
    list(APPEND PUBLIC_COMPILE_DEFINITIONS "OC_CLOUD")
    set(OC_TCP_ENABLED ON)
    set(OC_IPV4_ENABLED ON)
endif()

if(OC_INTROSPECTION_ENABLED)
    list(APPEND PUBLIC_COMPILE_DEFINITIONS "OC_INTROSPECTION")
    if(OC_IDD_API_ENABLED)
        list(APPEND PUBLIC_COMPILE_DEFINITIONS "OC_IDD_API")
    endif()
endif()

if(OC_TCP_ENABLED)
    list(APPEND PUBLIC_COMPILE_DEFINITIONS "OC_TCP")
endif()

if(OC_DISCOVERY_RESOURCE_OBSERVABLE_ENABLED)
    list(APPEND PRIVATE_COMPILE_DEFINITIONS "OC_DISCOVERY_RESOURCE_OBSERVABLE")
    list(APPEND TEST_COMPILE_DEFINITIONS "OC_DISCOVERY_RESOURCE_OBSERVABLE")
endif()

if(OC_REPRESENTATION_REALLOC_ENCODING_ENABLED)
    list(APPEND PRIVATE_COMPILE_DEFINITIONS "OC_REP_ENCODING_REALLOC")
    list(APPEND TEST_COMPILE_DEFINITIONS "OC_REP_ENCODING_REALLOC")
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
    if(BUILD_MBEDTLS)
        list(APPEND MBEDTLS_COMPILE_DEFINITIONS "OC_OSCORE")
    endif()
endif()

if(OC_IPV4_ENABLED)
    list(APPEND PUBLIC_COMPILE_DEFINITIONS "OC_IPV4")
endif()

if(OC_DNS_LOOKUP_IPV6_ENABLED)
    list(APPEND PRIVATE_COMPILE_DEFINITIONS "OC_DNS_LOOKUP_IPV6")
    list(APPEND TEST_COMPILE_DEFINITIONS "OC_DNS_LOOKUP_IPV6")
endif()

if(OC_MEMORY_TRACE_ENABLED)
    list(APPEND PRIVATE_COMPILE_DEFINITIONS "OC_MEMORY_TRACE")
    list(APPEND TEST_COMPILE_DEFINITIONS "OC_MEMORY_TRACE")
endif()

if (NOT("${OC_INOUT_BUFFER_SIZE}" STREQUAL ""))
    if(NOT OC_DYNAMIC_ALLOCATION_ENABLED)
        message(FATAL_ERROR "Cannot set custom static buffer size for network messages without dynamic allocation")
    endif()
    list(APPEND PUBLIC_COMPILE_DEFINITIONS "OC_INOUT_BUFFER_SIZE=(${OC_INOUT_BUFFER_SIZE})")
    list(APPEND MBEDTLS_COMPILE_DEFINITIONS "OC_INOUT_BUFFER_SIZE=(${OC_INOUT_BUFFER_SIZE})")
endif()

if (NOT("${OC_INOUT_BUFFER_POOL}" STREQUAL ""))
    if(NOT OC_DYNAMIC_ALLOCATION_ENABLED)
        message(FATAL_ERROR "Cannot set custom static pool size for network messages without dynamic allocation")
    endif()
    list(APPEND PUBLIC_COMPILE_DEFINITIONS "OC_INOUT_BUFFER_POOL=(${OC_INOUT_BUFFER_POOL})")
    list(APPEND MBEDTLS_COMPILE_DEFINITIONS "OC_INOUT_BUFFER_POOL=(${OC_INOUT_BUFFER_POOL})")
endif()

if (NOT("${OC_APP_DATA_BUFFER_SIZE}" STREQUAL ""))
    if(NOT OC_DYNAMIC_ALLOCATION_ENABLED)
        message(FATAL_ERROR "Cannot set custom static buffer size for application messages without dynamic allocation")
    endif()
    list(APPEND PUBLIC_COMPILE_DEFINITIONS "OC_APP_DATA_BUFFER_SIZE=(${OC_APP_DATA_BUFFER_SIZE})")
    list(APPEND MBEDTLS_COMPILE_DEFINITIONS "OC_APP_DATA_BUFFER_SIZE=(${OC_APP_DATA_BUFFER_SIZE})")
endif()

if (NOT("${OC_APP_DATA_BUFFER_POOL}" STREQUAL ""))
    if(NOT OC_DYNAMIC_ALLOCATION_ENABLED)
        message(FATAL_ERROR "Cannot set custom static pool size for application messages without dynamic allocation")
    endif()
    list(APPEND PUBLIC_COMPILE_DEFINITIONS "OC_APP_DATA_BUFFER_POOL=(${OC_APP_DATA_BUFFER_POOL})")
    list(APPEND MBEDTLS_COMPILE_DEFINITIONS "OC_APP_DATA_BUFFER_POOL=(${OC_APP_DATA_BUFFER_POOL})")
endif()

if(OC_VERSION_1_1_0_ENABLED)
    list(APPEND PUBLIC_COMPILE_DEFINITIONS "OC_SPEC_VER_OIC")
endif()

if(OC_ETAG_ENABLED)
    list(APPEND PUBLIC_COMPILE_DEFINITIONS "OC_ETAG")
endif()

if(OC_JSON_ENCODER_ENABLED)
    list(APPEND PUBLIC_COMPILE_DEFINITIONS "OC_JSON_ENCODER")
endif()

if(PLGD_DEV_TIME_ENABLED)
    list(APPEND PUBLIC_COMPILE_DEFINITIONS "PLGD_DEV_TIME")
    if(BUILD_MBEDTLS)
        list(APPEND MBEDTLS_COMPILE_DEFINITIONS "PLGD_DEV_TIME")
    endif()
endif()

if(BUILD_TESTING)
    list(APPEND PRIVATE_COMPILE_DEFINITIONS "OC_TEST")
    if(BUILD_MBEDTLS)
        list(APPEND MBEDTLS_COMPILE_DEFINITIONS "OC_TEST")
    endif()
endif()

if(MINGW)
    # Windows Vista or later
    list(APPEND PUBLIC_COMPILE_DEFINITIONS "WINVER=0x0600" "_WIN32_WINNT=0x0600")
    if(BUILD_MBEDTLS)
        list(APPEND MBEDTLS_COMPILE_DEFINITIONS "WINVER=0x0600" "_WIN32_WINNT=0x0600")
    endif()

    # force the use mingw_printf because the default doesn't support '%zu'
    list(APPEND PRIVATE_COMPILE_DEFINITIONS "__USE_MINGW_ANSI_STDIO=(1)")
    list(APPEND TEST_COMPILE_DEFINITIONS "__USE_MINGW_ANSI_STDIO=(1)")
    if(BUILD_MBEDTLS)
        list(APPEND MBEDTLS_COMPILE_DEFINITIONS "__USE_MINGW_ANSI_STDIO=(1)")
    endif()
endif()

if(MSVC)
    list(APPEND PRIVATE_COMPILE_DEFINITIONS "_CRT_SECURE_NO_WARNINGS=1")
endif()

if(OC_COVERAGE_ENABLED)
    list(APPEND PRIVATE_COMPILE_OPTIONS "--coverage")
endif()

# ####### Gather source files ########
file(GLOB COMMON_SRC
    ${PROJECT_SOURCE_DIR}/api/c-timestamp/timestamp_compare.c
    ${PROJECT_SOURCE_DIR}/api/c-timestamp/timestamp_format.c
    ${PROJECT_SOURCE_DIR}/api/c-timestamp/timestamp_valid.c
    ${PROJECT_SOURCE_DIR}/api/c-timestamp/timestamp_parse.c
    ${PROJECT_SOURCE_DIR}/port/common/*.c
    ${PROJECT_SOURCE_DIR}/util/*.c
)

if(UNIX)
    file(GLOB COMMON_POSIX_SRC
        ${PROJECT_SOURCE_DIR}/port/common/posix/*.c
    )
    list(APPEND COMMON_SRC ${COMMON_POSIX_SRC})
endif()

if(NOT OC_MEMORY_TRACE_ENABLED)
    list(REMOVE_ITEM COMMON_SRC
        ${PROJECT_SOURCE_DIR}/util/oc_mem_trace.c
    )
endif()

if(OC_PKI_ENABLED)
    list(APPEND COMMON_SRC
        ${PROJECT_SOURCE_DIR}/api/c-timestamp/timestamp_tm.c
    )
endif()

if(OC_JSON_ENCODER_ENABLED)
    file(GLOB JSMN_SRC
        ${PROJECT_SOURCE_DIR}/util/jsmn/*.c
    )
    list(APPEND COMMON_SRC ${JSMN_SRC})
endif()

if(PLGD_DEV_TIME_ENABLED)
    file(GLOB PLGD_SRC
        ${PROJECT_SOURCE_DIR}/api/plgd/*.c
    )
endif()

file(GLOB API_SRC
    ${PROJECT_SOURCE_DIR}/api/*.c
)
if(NOT OC_INTROSPECTION_ENABLED)
    list(REMOVE_ITEM API_SRC
        ${PROJECT_SOURCE_DIR}/api/oc_introspection.c
    )
endif()

file(GLOB SERVER_SRC
    ${PROJECT_SOURCE_DIR}/messaging/coap/*.c
    ${API_SRC}
    ${PLGD_SRC}
)
file(GLOB CLIENT_SRC
    ${SERVER_SRC}
    ${PROJECT_SOURCE_DIR}/api/client/*.c
)

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

    # fix oc_python compilation when OC_SECURITY is disabled
    file(GLOB PYTHON_SRC python/*.c)
endif()

if(OC_CLOUD_ENABLED)
    file(GLOB CLOUD_SRC api/cloud/*.c)
    set(CLOUD_INCLUDE_DIR ${PROJECT_SOURCE_DIR}/api/cloud)
endif()

# ####### Define link dependencies ########
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

if(OC_COVERAGE_ENABLED)
    list(APPEND PRIVATE_LINK_LIBS "--coverage")
endif()

# ####### Object libraries ########
if(OC_SECURITY_ENABLED)
    if(BUILD_MBEDTLS)
        include(deps/mbedtls.cmake)
        set(MBEDTLS_DEP mbedtls)
    else()
        find_package(MbedTLS REQUIRED)
        # Check that the Mbed TLS library is patched
        include(CheckSymbolExists)
        get_target_property(mbedtls_INTERFACE_INCLUDE_DIRECTORIES MbedTLS::mbedtls INTERFACE_INCLUDE_DIRECTORIES)
        set(CMAKE_REQUIRED_INCLUDES ${mbedtls_INTERFACE_INCLUDE_DIRECTORIES})
        check_symbol_exists(MBEDTLS_KEY_EXCHANGE_ECDH_ANON_ENABLED "mbedtls/mbedtls_config.h" MBEDTLS_PATCHED)
        if(NOT MBEDTLS_PATCHED)
            message(FATAL_ERROR "Detected Mbed TLS library is not patched!")
        endif()
        set(MBEDTLS_DEP MbedTLS::mbedtls)
    endif()

    list(APPEND PUBLIC_COMPILE_DEFINITIONS "__OC_PLATFORM")
endif()

if(BUILD_TINYCBOR)
    configure_file(${PROJECT_SOURCE_DIR}/deps/TinyCBORConfig.cmake.in ${PROJECT_SOURCE_DIR}/deps/tinycbor/TinyCBORConfig.cmake.in COPYONLY)
    configure_file(${PROJECT_SOURCE_DIR}/deps/tinycbor.cmake ${PROJECT_SOURCE_DIR}/deps/tinycbor/CMakeLists.txt COPYONLY)

    # freestanding sources are sufficient for our needs
    set(TINYCBOR_FREESTANDING_BUILD_ENABLED ON CACHE BOOL "Make freestanding build.")
    # use command-line parameters to enable TinyCBOR unit tests / helper executables
    option(ENABLE_EXECUTABLES "Build TinyCBOR executables." OFF)
    option(ENABLE_TESTING "Build TinyCBOR tests." OFF)

    if(OC_INSTALL_TINYCBOR)
        add_subdirectory(${PROJECT_SOURCE_DIR}/deps/tinycbor)
    else()
        add_subdirectory(${PROJECT_SOURCE_DIR}/deps/tinycbor EXCLUDE_FROM_ALL)
    endif()

    set(TINYCBOR_DEP tinycbor)
else()
    find_package(TinyCBOR REQUIRED)
    set(TINYCBOR_DEP TinyCBOR::tinycbor)
endif()

# enable clang-tidy for iotivity targets
oc_enable_clang_tidy()

add_library(client-common-obj OBJECT ${COMMON_SRC})
target_compile_definitions(client-common-obj PRIVATE ${PRIVATE_COMPILE_DEFINITIONS} PUBLIC ${PUBLIC_COMPILE_DEFINITIONS} "OC_CLIENT")
target_compile_options(client-common-obj PRIVATE ${PRIVATE_COMPILE_OPTIONS})
target_include_directories(client-common-obj PRIVATE ${PROJECT_SOURCE_DIR} ${PROJECT_SOURCE_DIR}/include ${PROJECT_SOURCE_DIR}/port ${PORT_INCLUDE_DIR})
target_link_libraries(client-common-obj PRIVATE ${TINYCBOR_DEP})

add_library(client-obj OBJECT ${CLIENT_SRC})
target_compile_definitions(client-obj PRIVATE ${PRIVATE_COMPILE_DEFINITIONS} PUBLIC ${PUBLIC_COMPILE_DEFINITIONS} "OC_CLIENT")
target_compile_options(client-obj PRIVATE ${PRIVATE_COMPILE_OPTIONS})
target_include_directories(client-obj PRIVATE ${PROJECT_SOURCE_DIR} ${PROJECT_SOURCE_DIR}/include ${PROJECT_SOURCE_DIR}/port ${PORT_INCLUDE_DIR})
target_link_libraries(client-obj PRIVATE ${TINYCBOR_DEP})
if(OC_SECURITY_ENABLED)
    target_link_libraries(client-obj PRIVATE ${MBEDTLS_DEP})
endif()

add_library(server-obj OBJECT ${COMMON_SRC} ${SERVER_SRC})
target_compile_definitions(server-obj PRIVATE ${PRIVATE_COMPILE_DEFINITIONS} PUBLIC ${PUBLIC_COMPILE_DEFINITIONS} "OC_SERVER")
target_compile_options(server-obj PRIVATE ${PRIVATE_COMPILE_OPTIONS})
target_include_directories(server-obj PRIVATE ${PROJECT_SOURCE_DIR} ${PROJECT_SOURCE_DIR}/include ${PROJECT_SOURCE_DIR}/port ${PORT_INCLUDE_DIR})
target_link_libraries(server-obj PRIVATE ${TINYCBOR_DEP})
if(OC_SECURITY_ENABLED)
    target_link_libraries(server-obj PRIVATE ${MBEDTLS_DEP})
endif()

add_library(client-server-obj OBJECT ${COMMON_SRC} ${CLIENT_SRC})
target_compile_definitions(client-server-obj PRIVATE ${PRIVATE_COMPILE_DEFINITIONS} PUBLIC ${PUBLIC_COMPILE_DEFINITIONS} "OC_CLIENT" "OC_SERVER")
target_compile_options(client-server-obj PRIVATE ${PRIVATE_COMPILE_OPTIONS})
target_include_directories(client-server-obj PRIVATE ${PROJECT_SOURCE_DIR} ${PROJECT_SOURCE_DIR}/include ${PROJECT_SOURCE_DIR}/port ${PORT_INCLUDE_DIR})
target_link_libraries(client-server-obj PRIVATE ${TINYCBOR_DEP})
if(OC_SECURITY_ENABLED)
    target_link_libraries(client-server-obj PRIVATE ${MBEDTLS_DEP})
endif()

if(OC_CLOUD_ENABLED)
    add_library(cloud-obj OBJECT ${CLOUD_SRC})
    target_compile_definitions(cloud-obj PRIVATE ${PRIVATE_COMPILE_DEFINITIONS} PUBLIC ${PUBLIC_COMPILE_DEFINITIONS} "OC_CLIENT" "OC_SERVER")
    target_compile_options(cloud-obj PRIVATE ${PRIVATE_COMPILE_OPTIONS})
    target_include_directories(cloud-obj PRIVATE ${PROJECT_SOURCE_DIR} ${PROJECT_SOURCE_DIR}/include ${PROJECT_SOURCE_DIR}/port ${PORT_INCLUDE_DIR})
    target_link_libraries(cloud-obj PRIVATE ${TINYCBOR_DEP})
    if(OC_SECURITY_ENABLED)
        target_link_libraries(cloud-obj PRIVATE ${MBEDTLS_DEP})
    endif()
endif()

if(OC_SECURITY_ENABLED)
    add_library(python-obj OBJECT ${PYTHON_SRC})
    target_compile_definitions(python-obj PRIVATE ${PRIVATE_COMPILE_DEFINITIONS} OC_LIBRARY_EXPORT PUBLIC ${PUBLIC_COMPILE_DEFINITIONS} "OC_LIBRARY" "OC_CLIENT")
    target_compile_options(python-obj PRIVATE ${PRIVATE_COMPILE_OPTIONS})
    set_property(TARGET python-obj PROPERTY C_VISIBILITY_PRESET hidden)
    set_property(TARGET python-obj PROPERTY VISIBILITY_INLINES_HIDDEN ON)
    target_include_directories(python-obj PRIVATE ${PROJECT_SOURCE_DIR} ${PROJECT_SOURCE_DIR}/include ${PROJECT_SOURCE_DIR}/port ${PORT_INCLUDE_DIR})
    target_link_libraries(python-obj PRIVATE ${TINYCBOR_DEP})
    target_link_libraries(python-obj PRIVATE ${MBEDTLS_DEP})
endif()

# ####### Compose static and shared libraries ########
# Client
set(client-lib-obj
    $<TARGET_OBJECTS:client-common-obj>
    $<TARGET_OBJECTS:client-obj>
)

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
target_link_libraries(client-static PUBLIC ${TINYCBOR_DEP})
if(OC_SECURITY_ENABLED)
    target_link_libraries(client-static PUBLIC ${MBEDTLS_DEP})
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
    target_link_libraries(client-shared PUBLIC ${TINYCBOR_DEP})
    if(OC_SECURITY_ENABLED)
        target_link_libraries(client-shared PUBLIC ${MBEDTLS_DEP})
    endif()

    set_target_properties(client-shared PROPERTIES
        OUTPUT_NAME "iotivity-lite-client"
        VERSION ${PROJECT_VERSION}
        SOVERSION ${PROJECT_VERSION_MAJOR}
    )
endif()

# Server
set(server-lib-obj
    $<TARGET_OBJECTS:server-obj>
)

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
target_link_libraries(server-static PUBLIC ${TINYCBOR_DEP})
if(OC_SECURITY_ENABLED)
    target_link_libraries(server-static PUBLIC ${MBEDTLS_DEP})
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
    target_link_libraries(server-shared PUBLIC ${TINYCBOR_DEP})
    if(OC_SECURITY_ENABLED)
        target_link_libraries(server-shared PUBLIC ${MBEDTLS_DEP})
    endif()

    set_target_properties(server-shared PROPERTIES
        OUTPUT_NAME "iotivity-lite-server"
        VERSION ${PROJECT_VERSION}
        SOVERSION ${PROJECT_VERSION_MAJOR}
    )
endif()

# Client-Server
set(client-server-lib-obj
    $<TARGET_OBJECTS:client-server-obj>
)

if(OC_CLOUD_ENABLED)
    list(APPEND client-server-lib-obj $<TARGET_OBJECTS:cloud-obj>)
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
if(OC_CLOUD_ENABLED)
    target_include_directories(client-server-static PUBLIC $<BUILD_INTERFACE:${CLOUD_INCLUDE_DIR}>)
endif()
target_link_libraries(client-server-static PUBLIC ${TINYCBOR_DEP})
if(OC_SECURITY_ENABLED)
    target_link_libraries(client-server-static PUBLIC ${MBEDTLS_DEP})
endif()

if(OC_COVERAGE_ENABLED)
    target_compile_options(client-server-static PRIVATE "--coverage")
    target_link_libraries(client-server-static PRIVATE "--coverage")
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
    target_link_libraries(client-server-shared PUBLIC ${TINYCBOR_DEP})
    if(OC_SECURITY_ENABLED)
        target_link_libraries(client-server-shared PUBLIC ${MBEDTLS_DEP})
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

if(OC_SECURITY_ENABLED)
    # Python client
    set(client-python-lib-obj
        $<TARGET_OBJECTS:client-common-obj>
        $<TARGET_OBJECTS:client-obj>
        $<TARGET_OBJECTS:python-obj>
    )

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
    target_link_libraries(client-python-shared PUBLIC ${TINYCBOR_DEP})
    target_link_libraries(client-python-shared PUBLIC ${MBEDTLS_DEP})

    set_target_properties(client-python-shared PROPERTIES
        OUTPUT_NAME "iotivity-lite-client-python"
        VERSION ${PROJECT_VERSION}
        SOVERSION ${PROJECT_VERSION_MAJOR}
    )
endif()

# ####### Units tests (UNIX only) ########
if(BUILD_TESTING AND(UNIX OR MINGW))
    include(CTest)
    enable_language(CXX)
    set(CMAKE_CXX_STANDARD 17)
    set(CMAKE_CXX_STANDARD_REQUIRED ON)
    set(CMAKE_CXX_EXTENSIONS OFF)
    list(APPEND TEST_COMPILE_DEFINITIONS  "OC_CLIENT" "OC_SERVER" "OC_TEST")
    list(APPEND TEST_COMPILE_OPTIONS "-fpermissive" "-Wno-deprecated-declarations" "-Wno-error")
    list(APPEND TEST_LINK_LIBS client-server-static gtest_main)
    if(OC_SECURITY_ENABLED)
        list(APPEND TEST_LINK_LIBS ${TINYCBOR_DEP} ${MBEDTLS_DEP})
    endif()
    if(UNIX)
        list(APPEND TEST_LINK_LIBS Threads::Threads)
    endif()

    try_compile(HAVE_FLOAT16 ${CMAKE_BINARY_DIR} ${PROJECT_SOURCE_DIR}/tools/test_float16.c)
    if(HAVE_FLOAT16)
        list(APPEND TEST_COMPILE_DEFINITIONS "HAVE_FLOAT16")
    endif()

    # Disable clang-tidy for gtest
    oc_disable_clang_tidy()

    # Build googletest
    add_subdirectory(${PROJECT_SOURCE_DIR}/deps/gtest gtest)

    set(OC_UNITTESTS)
    # Helper macro to build unit test
    macro(oc_package_add_test)
        set(options)
        set(oneValueArgs TARGET)
        set(multiValueArgs ENVIRONMENT FILES SOURCES)
        cmake_parse_arguments(OC_PACKAGE_ADD_TEST "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})

        add_executable(${OC_PACKAGE_ADD_TEST_TARGET} ${OC_PACKAGE_ADD_TEST_SOURCES})
        target_compile_options(${OC_PACKAGE_ADD_TEST_TARGET} PRIVATE ${TEST_COMPILE_OPTIONS})
        target_compile_definitions(${OC_PACKAGE_ADD_TEST_TARGET} PRIVATE ${PUBLIC_COMPILE_DEFINITIONS} ${TEST_COMPILE_DEFINITIONS})
        target_include_directories(${OC_PACKAGE_ADD_TEST_TARGET} SYSTEM PRIVATE ${PROJECT_SOURCE_DIR}/deps/gtest/include)
        target_include_directories(${OC_PACKAGE_ADD_TEST_TARGET} PRIVATE
            ${PROJECT_SOURCE_DIR}
            ${PROJECT_SOURCE_DIR}/include
            ${PORT_INCLUDE_DIR}
            ${PROJECT_SOURCE_DIR}/messaging/coap
        )

        if(OC_SECURITY_ENABLED)
            target_include_directories(${OC_PACKAGE_ADD_TEST_TARGET} PRIVATE
                ${PROJECT_SOURCE_DIR}/security
            )
        endif()

        if(OC_CLOUD_ENABLED)
            target_include_directories(${OC_PACKAGE_ADD_TEST_TARGET} PRIVATE ${PROJECT_SOURCE_DIR}/api/cloud)
        endif()

        target_link_libraries(${OC_PACKAGE_ADD_TEST_TARGET} PRIVATE ${TEST_LINK_LIBS})
        if(OC_COMPILER_IS_GCC OR OC_COMPILER_IS_CLANG)
            target_link_libraries(${OC_PACKAGE_ADD_TEST_TARGET} PRIVATE "-Wl,--unresolved-symbols=ignore-in-shared-libs")
        endif()
        add_test(NAME ${OC_PACKAGE_ADD_TEST_TARGET} COMMAND ${OC_PACKAGE_ADD_TEST_TARGET})

        set_property(TEST ${OC_PACKAGE_ADD_TEST_TARGET} PROPERTY FOLDER unittests)
        set_property(TEST ${OC_PACKAGE_ADD_TEST_TARGET} PROPERTY LABELS oc-unittest)
        if(OC_PACKAGE_ADD_TEST_ENVIRONMENT)
            set_property(TEST ${OC_PACKAGE_ADD_TEST_TARGET} PROPERTY ENVIRONMENT "${OC_PACKAGE_ADD_TEST_ENVIRONMENT}")
        endif()

        if(OC_PACKAGE_ADD_TEST_FILES)
            set(OC_PACKAGE_ADD_TEST_FILENAMES)
            set(OC_PACKAGE_ADD_TEST_OUT_FILES)
            foreach(OC_PACKAGE_ADD_TEST_FILE "${OC_PACKAGE_ADD_TEST_FILES}")
                get_filename_component(OC_PACKAGE_ADD_TEST_FILENAME ${OC_PACKAGE_ADD_TEST_FILE} NAME)
                list(APPEND OC_PACKAGE_ADD_TEST_FILENAMES ${OC_PACKAGE_ADD_TEST_FILENAME})
                list(APPEND OC_PACKAGE_ADD_TEST_OUT_FILES ${PROJECT_BINARY_DIR}/${OC_PACKAGE_ADD_TEST_FILENAME})
            endforeach()

            add_custom_target(${OC_PACKAGE_ADD_TEST_TARGET}-files
                COMMAND ${CMAKE_COMMAND} -E copy ${OC_PACKAGE_ADD_TEST_FILES} ${PROJECT_BINARY_DIR}
                BYPRODUCTS ${OC_PACKAGE_ADD_TEST_OUT_FILES}
            )
            add_dependencies(${OC_PACKAGE_ADD_TEST_TARGET} ${OC_PACKAGE_ADD_TEST_TARGET}-files)
        endif()

        list(APPEND OC_UNITTESTS ${OC_PACKAGE_ADD_TEST_TARGET})
    endmacro()

    file(GLOB COMMONTEST_SRC tests/gtest/*.cpp tests/gtest/tls/*.cpp)

    # Unit tests
    file(GLOB APITEST_SRC api/unittest/*.cpp api/unittest/encoder/*.cpp api/client/unittest/*.cpp)
    set(apitest_files)
    if (OC_INTROSPECTION_ENABLED AND OC_IDD_API_ENABLED)
        set(apitest_files ${PROJECT_SOURCE_DIR}/api/unittest/introspectiontest_IDD.cbor)
    endif()
    oc_package_add_test(
        TARGET apitest
        SOURCES ${COMMONTEST_SRC} ${APITEST_SRC}
        FILES ${apitest_files}
        ENVIRONMENT "ASAN_OPTIONS=${OC_ASAN_OPTIONS}"
                    "TSAN_OPTIONS=${OC_TSAN_OPTIONS}"
                    "UBSAN_OPTIONS=${OC_UBSAN_OPTIONS}"
    )

    file(GLOB TIMESTAMPTEST_SRC api/c-timestamp/unittest/*.cpp)
    oc_package_add_test(
        TARGET timestamptest
        SOURCES ${TIMESTAMPTEST_SRC}
        ENVIRONMENT "ASAN_OPTIONS=${OC_ASAN_OPTIONS}"
                    "TSAN_OPTIONS=${OC_TSAN_OPTIONS}"
                    "UBSAN_OPTIONS=${OC_UBSAN_OPTIONS}"
    )

    file(GLOB PLATFORMTEST_SRC port/unittest/*.cpp)
    file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/storage_test)
    oc_package_add_test(
        TARGET platformtest
        SOURCES ${COMMONTEST_SRC} ${PLATFORMTEST_SRC}
        ENVIRONMENT "ASAN_OPTIONS=${OC_ASAN_OPTIONS}"
                    "TSAN_OPTIONS=${OC_TSAN_OPTIONS}"
                    "UBSAN_OPTIONS=${OC_UBSAN_OPTIONS}"
    )

    file(GLOB MESSAGINGTEST_SRC messaging/coap/unittest/*.cpp)
    oc_package_add_test(
        TARGET messagingtest
        SOURCES ${COMMONTEST_SRC} ${MESSAGINGTEST_SRC}
        ENVIRONMENT "ASAN_OPTIONS=${OC_ASAN_OPTIONS}"
                    "TSAN_OPTIONS=${OC_TSAN_OPTIONS}"
                    "UBSAN_OPTIONS=${OC_UBSAN_OPTIONS}"
    )

    if(OC_SECURITY_ENABLED)
        file(GLOB SECURITYTEST_SRC security/unittest/*.cpp)
        oc_package_add_test(
            TARGET securitytest
            SOURCES ${COMMONTEST_SRC} ${SECURITYTEST_SRC}
            ENVIRONMENT "ASAN_OPTIONS=${OC_ASAN_OPTIONS}"
                        "TSAN_OPTIONS=${OC_TSAN_OPTIONS}"
                        "UBSAN_OPTIONS=${OC_UBSAN_OPTIONS}"
        )

        file(COPY ${PROJECT_SOURCE_DIR}/apps/pki_certs
            DESTINATION ${CMAKE_CURRENT_BINARY_DIR}
        )
    endif()

    file(GLOB UTILTEST_SRC util/unittest/*.cpp)
    oc_package_add_test(
        TARGET utiltest
        SOURCES ${COMMONTEST_SRC} ${UTILTEST_SRC}
        ENVIRONMENT "ASAN_OPTIONS=${OC_ASAN_OPTIONS}"
                    "TSAN_OPTIONS=${OC_TSAN_OPTIONS}"
                    "UBSAN_OPTIONS=${OC_UBSAN_OPTIONS}"
    )

    if(OC_CLOUD_ENABLED)
        file(GLOB CLOUDTEST_SRC api/cloud/unittest/*.cpp)
        file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/storage_cloud)
        oc_package_add_test(
            TARGET cloudtest
            SOURCES ${COMMONTEST_SRC} ${CLOUDTEST_SRC}
            ENVIRONMENT "ASAN_OPTIONS=${OC_ASAN_OPTIONS}"
                        "TSAN_OPTIONS=${OC_TSAN_OPTIONS}"
                        "UBSAN_OPTIONS=${OC_UBSAN_OPTIONS}"
        )
    endif()

    if(OC_SECURITY_ENABLED AND OC_DYNAMIC_ALLOCATION_ENABLED)
        file(GLOB PYTHONLIBTEST_SRC python/oc_python.c python/unittest/*.cpp)
        oc_package_add_test(TARGET pythonlibtest SOURCES ${PYTHONLIBTEST_SRC})
    endif()

    if(UNIX AND NOT OC_TSAN_ENABLED)
        # install https://github.com/wolfcw/libfaketime for this test suit to run
        find_library(FAKETIME_LIBRARY
            NAMES libfaketimeMT.so.1
            PATH_SUFFIXES faketime
        )
        if (FAKETIME_LIBRARY)
            file(GLOB FAKETIMETEST_SRC tests/libfaketime/unittest/*.cpp)
            oc_package_add_test(
                TARGET faketimetest
                SOURCES ${COMMONTEST_SRC} ${FAKETIMETEST_SRC}
                ENVIRONMENT "ASAN_OPTIONS=${OC_ASAN_OPTIONS}:verify_asan_link_order=0"
                            "LD_PRELOAD=/usr/local/lib/faketime/libfaketimeMT.so.1"
                            "FAKETIME_DONT_FAKE_MONOTONIC=1"
                            "FAKETIME_TIMESTAMP_FILE="
                            "FAKETIME_UPDATE_TIMESTAMP_FILE="
                            "FAKETIME_DONT_RESET="
                            "FAKETIME_NO_CACHE="
                            "FAKETIME_CACHE_DURATION="
            )
            target_link_libraries(faketimetest PRIVATE ${FAKETIME_LIBRARY})
        endif()
    endif()

    if(OC_FAKETIMETEST_FORCED)
        file(GLOB FAKETIMETEST_SRC tests/libfaketime/unittest/*.cpp)
        oc_package_add_test(
            TARGET faketimetest
            SOURCES ${COMMONTEST_SRC} ${FAKETIMETEST_SRC}
        )
    endif()

    add_custom_target(
        oc-unittests
        DEPENDS ${OC_UNITTESTS}
    )

    # reenable clang-tidy for any remaining targets
    oc_enable_clang_tidy()
endif()

# ####### Generate pkg-config and cmake package files ########
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
    set(extra_requires "tinycbor")
    if(OC_SECURITY_ENABLED)
        set(extra_libs "-lmbedtls -lmbedx509 -lmbedcrypto")
    endif()

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

# ####### Installation ########
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
    FILE iotivity-liteTargets.cmake
    NAMESPACE iotivity-lite::
    DESTINATION ${TARGETS_INSTALL_DIR}
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
    FILES_MATCHING
    PATTERN "*.h"
    PATTERN "oc_etag.h" EXCLUDE
    PATTERN "oc_introspection.h" EXCLUDE
    PATTERN "server_introspection.dat.h" EXCLUDE
    PATTERN "plgd" EXCLUDE
)

if (OC_INTROSPECTION_ENABLED)
    if (OC_IDD_API_ENABLED)
        set(INTROSPECTION_HEADERS include/oc_introspection.h)
    else()
        set(INTROSPECTION_HEADERS include/server_introspection.dat.h)
    endif()
    install(FILES ${INTROSPECTION_HEADERS}
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/iotivity-lite COMPONENT dev
    )
endif()

if (PLGD_DEV_TIME_ENABLED)
    install(DIRECTORY include/plgd
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/iotivity-lite COMPONENT dev
        FILES_MATCHING
        PATTERN "*.h"
    )
endif()

if(OC_ETAG_ENABLED)
    install(FILES include/oc_etag.h
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/iotivity-lite COMPONENT dev
    )
endif()

install(FILES ${PORT_INCLUDE_DIR}/oc_config.h
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/iotivity-lite COMPONENT dev
)

file(GLOB HEADERS_COAP ${PROJECT_SOURCE_DIR}/messaging/coap/*.h)
list(FILTER HEADERS_COAP EXCLUDE REGEX ".*_internal\\.h$")
install(FILES ${HEADERS_COAP}
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/iotivity-lite/messaging/coap COMPONENT dev
)

file(GLOB HEADERS_PORT ${PROJECT_SOURCE_DIR}/port/*.h)
list(FILTER HEADERS_PORT EXCLUDE REGEX ".*_internal\\.h$")
install(FILES ${HEADERS_PORT}
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/iotivity-lite/port COMPONENT dev
)

file(GLOB HEADERS_UTIL ${PROJECT_SOURCE_DIR}/util/*.h)
list(FILTER HEADERS_UTIL EXCLUDE REGEX ".*_internal\\.h$")
install(FILES ${HEADERS_UTIL}
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/iotivity-lite/util COMPONENT dev
)
file(GLOB HEADERS_UTIL_PT ${PROJECT_SOURCE_DIR}/util/pt/*.h)
list(FILTER HEADERS_UTIL_PT EXCLUDE REGEX ".*_internal\\.h$")
install(FILES ${HEADERS_UTIL_PT}
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/iotivity-lite/util/pt COMPONENT dev
)

# ####### Code formatting ########
if(PROJECT_SOURCE_DIR STREQUAL CMAKE_SOURCE_DIR)
    # Add clang-format target
    add_custom_target(format
        COMMAND ${CMAKE_COMMAND} -P ${PROJECT_SOURCE_DIR}/tools/clang-format.cmake
        WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
    )
endif()

# ####### Sub-projects ########
if(BUILD_EXAMPLE_APPLICATIONS)
    add_subdirectory(onboarding_tool)
    add_subdirectory(apps)
endif()

if(BUILD_TESTING AND UNIX)
    add_subdirectory(tests)
endif()
