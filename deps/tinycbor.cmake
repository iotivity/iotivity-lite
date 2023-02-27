cmake_minimum_required(VERSION 3.16)

project(tinyCBOR
        VERSION 0.6.0
        DESCRIPTION "A tiny CBOR encoder and decoder library."
        LANGUAGES C CXX
)

string(REGEX MATCH "Clang" CMAKE_COMPILER_IS_CLANG "${CMAKE_C_COMPILER_ID}")
string(REGEX MATCH "GNU" CMAKE_COMPILER_IS_GNU "${CMAKE_C_COMPILER_ID}")
string(REGEX MATCH "MSVC" CMAKE_COMPILER_IS_MSVC "${CMAKE_C_COMPILER_ID}")

set(TINYCBOR_FREESTANDING_BUILD_ENABLED OFF CACHE BOOL "Make freestanding build.")

option(ENABLE_EXECUTABLES "Build TinyCBOR programs." ON)
if (CMAKE_COMPILER_IS_MSVC)
    option(ENABLE_TESTING "Build TinyCBOR tests." OFF)
else()
    option(ENABLE_TESTING "Build TinyCBOR tests." ON)
endif()

option(USE_STATIC_TINYCBOR_LIBRARY "Build TinyCBOR static library." ON)
option(USE_SHARED_TINYCBOR_LIBRARY "Build TinyCBOR shared library." OFF)

if (NOT USE_STATIC_TINYCBOR_LIBRARY AND NOT USE_SHARED_TINYCBOR_LIBRARY)
    message(FATAL_ERROR "Need to allow at least one of static or shared TinyCBOR build")
endif()

include(CheckSymbolExists)
list(APPEND CMAKE_REQUIRED_DEFINITIONS -D_GNU_SOURCE)
check_symbol_exists(open_memstream "stdio.h" HAVE_OPEN_MEMSTREAM)
check_symbol_exists(fopencookie "stdio.h" HAVE_FOPENCOOKIE)
check_symbol_exists(funopen "stdio.h" HAVE_FUNOPEN)
list(REMOVE_ITEM CMAKE_REQUIRED_DEFINITIONS -D_GNU_SOURCE)

set(TINYCBOR_ROOT_DIR ${PROJECT_SOURCE_DIR})

# get version and soversion from VERSION file
file(READ ${TINYCBOR_ROOT_DIR}/VERSION TINYCBOR_VERSION)
string(STRIP "${TINYCBOR_VERSION}" TINYCBOR_VERSION)
if (NOT TINYCBOR_VERSION)
    message(FATAL_ERROR "Failed to read VERSION file")
endif()
string(REGEX MATCH "^[0-9]+\.[0-9]+" TINYCBOR_SOVERSION "${TINYCBOR_VERSION}")
if (NOT TINYCBOR_SOVERSION)
    message(FATAL_ERROR "Failed to parse SOVERSION")
endif()

set(TINYCBOR_COMPILE_DEFINITIONS)

if (CMAKE_COMPILER_IS_CLANG OR CMAKE_COMPILER_IS_GNU)
    set(TINYCBOR_COMPILE_OPTIONS
        -Wall
        -Wextra
    )
    set(TINYCBOR_C_COMPILE_OPTIONS
        -Werror=incompatible-pointer-types
        -Werror=implicit-function-declaration
        -Werror=int-conversion
    )
endif()

# Compiler and linker flags
if(CMAKE_COMPILER_IS_GNU)
	set(TINYCBOR_COMPILE_OPTIONS_RELEASE -fdata-sections -ffunction-sections)
	# -Wl,--as-needed       = Only link libraries that export symbols used by the binary
	# -Wl,--gc-sections     = Remove unused code resulting from -fdata-sections and -function-sections
	set(TINYCBOR_LINK_OPTIONS_RELEASE -Wl,--as-needed -Wl,--gc-sections)
endif()

if(CMAKE_COMPILER_IS_CLANG)
	# -Wl,-dead_strip       = Remove unused code
	set(TINYCBOR_LINK_OPTIONS_RELEASE -Wl,-dead_strip)
endif()

set(TINYCBOR_SRC_DIR ${TINYCBOR_ROOT_DIR}/src)
set(TINYCBOR_FREESTANDING_SOURCES
    ${TINYCBOR_SRC_DIR}/cborencoder_close_container_checked.c
    ${TINYCBOR_SRC_DIR}/cborencoder_float.c
    ${TINYCBOR_SRC_DIR}/cborencoder.c
    ${TINYCBOR_SRC_DIR}/cborerrorstrings.c
    ${TINYCBOR_SRC_DIR}/cborparser.c
    ${TINYCBOR_SRC_DIR}/cborparser_float.c
    ${TINYCBOR_SRC_DIR}/cborpretty.c
)

set(TINYCBOR_SOURCES ${TINYCBOR_FREESTANDING_SOURCES})
if (NOT TINYCBOR_FREESTANDING_BUILD_ENABLED)
    list(APPEND TINYCBOR_SOURCES
        ${TINYCBOR_SRC_DIR}/cborparser_dup_string.c
        ${TINYCBOR_SRC_DIR}/cborpretty_stdio.c
        ${TINYCBOR_SRC_DIR}/cbortojson.c
        ${TINYCBOR_SRC_DIR}/cborvalidation.c
    )
endif()

if (NOT TINYCBOR_FREESTANDING_BUILD_ENABLED AND NOT HAVE_OPEN_MEMSTREAM)
    if (NOT HAVE_FOPENCOOKIE AND NOT HAVE_FUNOPEN)
        list(APPEND TINYCBOR_COMPILE_DEFINITIONS WITHOUT_OPEN_MEMSTREAM)
        message(WARNING "funopen and fopencookie unavailable, open_memstream can not be implemented and conversion to JSON will not work properly!")
    else()
        list(APPEND TINYCBOR_SOURCES ${TINYCBOR_SRC_DIR}/open_memstream.c)
    endif()
endif()

set(TINYCBOR_PUBLIC_HEADERS
    ${TINYCBOR_SRC_DIR}/cbor.h
    ${TINYCBOR_SRC_DIR}/cborjson.h
    ${TINYCBOR_SRC_DIR}/tinycbor-version.h
)

set(tinycbor_target    "tinycbor")

if (USE_STATIC_TINYCBOR_LIBRARY)
    set(tinycbor_static_target ${tinycbor_target})
endif()

set(TINYCBOR_LIBRARIES ${tinycbor_target})
set(TINYCBOR_EXECUTABLES)

if(USE_STATIC_TINYCBOR_LIBRARY AND USE_SHARED_TINYCBOR_LIBRARY)
    string(APPEND tinycbor_static_target    "_static")
    list(APPEND TINYCBOR_LIBRARIES ${tinycbor_static_target})
endif()

macro(tinycbor_target_compile_and_link_options TARGET)
    target_compile_definitions(${TARGET} PRIVATE ${TINYCBOR_COMPILE_DEFINITIONS})
    target_compile_options(${TARGET} PRIVATE ${TINYCBOR_COMPILE_OPTIONS})
    target_compile_options(${TARGET} PRIVATE "$<$<COMPILE_LANGUAGE:C>:${TINYCBOR_C_COMPILE_OPTIONS}>")
    target_compile_options(${TARGET} PRIVATE "$<$<OR:$<CONFIG:Release>,$<CONFIG:RelWithDebInfo>,$<CONFIG:MinSizeRel>>:${TINYCBOR_COMPILE_OPTIONS_RELEASE}>")
    target_link_options(${TARGET} PRIVATE "$<$<OR:$<CONFIG:Release>,$<CONFIG:RelWithDebInfo>,$<CONFIG:MinSizeRel>>:${TINYCBOR_LINK_OPTIONS_RELEASE}>")
endmacro()

if(USE_STATIC_TINYCBOR_LIBRARY)
    add_library(${tinycbor_static_target} STATIC ${TINYCBOR_SOURCES})
    set_target_properties(${tinycbor_static_target} PROPERTIES OUTPUT_NAME tinycbor)
    tinycbor_target_compile_and_link_options(${tinycbor_static_target})

    if (TINYCBOR_FREESTANDING_BUILD_ENABLED)
        add_library(${tinycbor_static_target}-freestanding STATIC ${TINYCBOR_FREESTANDING_SOURCES})
        set_target_properties(${tinycbor_static_target}-freestanding PROPERTIES OUTPUT_NAME tinycbor-freestanding)
        tinycbor_target_compile_and_link_options(${tinycbor_static_target}-freestanding)
    endif()
endif()

if(USE_SHARED_TINYCBOR_LIBRARY)
    add_library(${tinycbor_target} SHARED ${TINYCBOR_SOURCES})
    set_target_properties(${tinycbor_target}
        PROPERTIES VERSION "${TINYCBOR_VERSION}"
                   SOVERSION "${TINYCBOR_SOVERSION}"
    )
    tinycbor_target_compile_and_link_options(${tinycbor_target})

    if (TINYCBOR_FREESTANDING_BUILD_ENABLED)
        add_library(${tinycbor_target}-freestanding SHARED ${TINYCBOR_FREESTANDING_SOURCES})
        set_target_properties(${tinycbor_target}-freestanding
            PROPERTIES VERSION "${TINYCBOR_VERSION}"
                       SOVERSION "${TINYCBOR_SOVERSION}"
        )
        tinycbor_target_compile_and_link_options(${tinycbor_target}-freestanding)
    endif()
endif()

if (ENABLE_EXECUTABLES)
    set(TINYCBOR_TOOLS_DIR ${TINYCBOR_ROOT_DIR}/tools)
    find_package(cJSON)

    # json2cbor
    if (cJSON_FOUND)
        add_executable(json2cbor ${TINYCBOR_TOOLS_DIR}/json2cbor/json2cbor.c)
        target_include_directories(json2cbor PRIVATE ${CJSON_INCLUDE_DIRS})
        target_link_libraries(json2cbor PRIVATE ${CJSON_LIBRARIES} ${tinycbor_target})
        set_target_properties(json2cbor PROPERTIES INSTALL_RPATH_USE_LINK_PATH ON)
        tinycbor_target_compile_and_link_options(json2cbor)

        list(APPEND TINYCBOR_EXECUTABLES json2cbor)
    endif()

    if (NOT TINYCBOR_FREESTANDING_BUILD_ENABLED)
        # cbordump
        add_executable(cbordump ${TINYCBOR_TOOLS_DIR}/cbordump/cbordump.c)
        target_link_libraries(cbordump PRIVATE ${tinycbor_target})
        tinycbor_target_compile_and_link_options(cbordump)

        list(APPEND TINYCBOR_EXECUTABLES cbordump)
    endif()
endif()

include(GNUInstallDirs)

foreach(target IN LISTS TINYCBOR_LIBRARIES)
    set_target_properties(${target} PROPERTIES PUBLIC_HEADER "${TINYCBOR_PUBLIC_HEADERS}")

    target_include_directories(${target}
        PUBLIC $<BUILD_INTERFACE:${TINYCBOR_SRC_DIR}/>
               $<INSTALL_INTERFACE:include/tinycbor/>
    )
    install(
        TARGETS ${target}
        EXPORT TinyCBORTargets
        DESTINATION lib
        PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/tinycbor
        PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ
    )
endforeach()

foreach(exe IN LISTS TINYCBOR_EXECUTABLES)
    install(
        TARGETS ${exe}
        EXPORT TinyCBORTargets
        DESTINATION bin
        PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
    )
endforeach()

# Generate pkg-config files
set(prefix ${CMAKE_INSTALL_PREFIX})
set(exec_prefix "\${prefix}")
set(libdir "\${prefix}/${CMAKE_INSTALL_LIBDIR}")
set(includedir "\${prefix}/${CMAKE_INSTALL_INCLUDEDIR}")
set(version ${TINYCBOR_VERSION})

configure_file(
    "${TINYCBOR_ROOT_DIR}/tinycbor.pc.in"
    tinycbor.pc
    @ONLY
)

# Install pkg-config files
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/tinycbor.pc
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig
)

# Generate CMake package files
include(CMakePackageConfigHelpers)
configure_package_config_file(TinyCBORConfig.cmake.in ${CMAKE_CURRENT_BINARY_DIR}/TinyCBORConfig.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/tinycbor
)
write_basic_package_version_file(TinyCBORConfigVersion.cmake
    VERSION ${TINYCBOR_VERSION}
    COMPATIBILITY SameMajorVersion
)

if(WIN32 AND NOT CYGWIN)
    set(TARGETS_INSTALL_DIR cmake)
else()
    set(TARGETS_INSTALL_DIR ${CMAKE_INSTALL_LIBDIR}/cmake/tinycbor)
endif()

# Install CMake package files
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/TinyCBORConfig.cmake
              ${CMAKE_CURRENT_BINARY_DIR}/TinyCBORConfigVersion.cmake
    DESTINATION ${TARGETS_INSTALL_DIR}
)

# Generate CMake targets file
export(EXPORT TinyCBORTargets
    NAMESPACE TinyCBOR::
    FILE TinyCBORTargets.cmake
)

# Install CMake targets file
install(EXPORT TinyCBORTargets
    FILE TinyCBORTargets.cmake
    NAMESPACE TinyCBOR::
    DESTINATION ${TARGETS_INSTALL_DIR}
)

# TODO: use CPACK to generate package
# if(CMAKE_VERSION VERSION_GREATER 3.15 OR CMAKE_VERSION VERSION_EQUAL 3.15)
#     # Do not export the package by default
#     cmake_policy(SET CMP0090 NEW)

#     # Make this package visible to the system
#     export(PACKAGE TinyCBOR)
# endif()

if (ENABLE_TESTING)
    enable_testing()
    find_package(Qt5Test REQUIRED)
    set(CMAKE_AUTOMOC ON)

    set(TINYCBOR_TESTS_DIR ${TINYCBOR_ROOT_DIR}/tests)

    macro(add_qt_test TESTNAME)
        add_executable(${TESTNAME} ${ARGN})
        target_link_libraries(${TESTNAME} PRIVATE ${tinycbor_target} Qt5::Test)
        tinycbor_target_compile_and_link_options(${TESTNAME})
        add_test(NAME ${TESTNAME} COMMAND ${TESTNAME})
    endmacro()

    macro(add_cxx_qt_test TESTNAME)
        add_qt_test(${TESTNAME} ${ARGN})
        set_property(TARGET ${TESTNAME} PROPERTY CXX_STANDARD 17)
        set_property(TARGET ${TESTNAME} PROPERTY CXX_EXTENSIONS OFF)
        tinycbor_target_compile_and_link_options(${TESTNAME})
        target_compile_options(${TESTNAME} PRIVATE "-fpermissive")
    endmacro()

    add_qt_test(c90 ${TINYCBOR_TESTS_DIR}/c90/tst_c90.c)
    set_property(TARGET c90 PROPERTY C_STANDARD 90)
    set_property(TARGET c90 PROPERTY C_EXTENSIONS OFF)

    add_cxx_qt_test(cpp ${TINYCBOR_TESTS_DIR}/cpp/tst_cpp.cpp)

    add_cxx_qt_test(encoder ${TINYCBOR_TESTS_DIR}/encoder/tst_encoder.cpp)

    add_cxx_qt_test(parser ${TINYCBOR_TESTS_DIR}/parser/tst_parser.cpp)
    target_compile_definitions(parser PRIVATE "CBOR_PARSER_MAX_RECURSIONS=16")

    add_cxx_qt_test(tojson ${TINYCBOR_TESTS_DIR}/tojson/tst_tojson.cpp)
endif()
