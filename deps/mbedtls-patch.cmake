# This is the iotivity-lite patch tool (originally written in make) ported to cmake so
# that it can run cross-platform. It applies the collection of patches in iotivity-lite/patches/
# to mbedtls. This should be run in the Iotivity source directory.
cmake_minimum_required(VERSION 3.10)

# Find git
find_package(Git)

if(NOT Git_FOUND)
	message(FATAL_ERROR "Could not find 'git' tool for iotivity mbedtls patching")
endif()

message("iotivity patch utils found")

set(IOTIVITY_SRC_DIR "${CMAKE_CURRENT_SOURCE_DIR}")
set(MBEDTLS_SRC_DIR "${IOTIVITY_SRC_DIR}/deps/mbedtls")
set(IOTIVITY_PATCH_DIR "${IOTIVITY_SRC_DIR}/patches")

if(EXISTS "${MBEDTLS_SRC_DIR}/.git")
	message("cleaning mbedtls...")
	execute_process(COMMAND ${GIT_EXECUTABLE} -C ${MBEDTLS_SRC_DIR} clean -fdx)
	execute_process(COMMAND ${GIT_EXECUTABLE} -C ${MBEDTLS_SRC_DIR} reset --hard)
	message("mbedtls cleaned")
endif()

execute_process(
	COMMAND ${GIT_EXECUTABLE} -C ${MBEDTLS_SRC_DIR} rev-parse --is-shallow-repository
	RESULT_VARIABLE IS_SHALLOW
	OUTPUT_QUIET
)

if(IS_SHALLOW EQUAL 0)
	execute_process(COMMAND ${GIT_EXECUTABLE} -C ${MBEDTLS_SRC_DIR} fetch --tags)	
else()
	execute_process(COMMAND ${GIT_EXECUTABLE} -C ${MBEDTLS_SRC_DIR} fetch --unshallow --tags)
endif()

if(BUILD_MBEDTLS_FORCE_3_5_0)
	message(STATUS "Using mbedTLS v3.5.0")
	execute_process(COMMAND ${GIT_EXECUTABLE} -C ${MBEDTLS_SRC_DIR} checkout v3.5.0)
	execute_process(COMMAND ${GIT_EXECUTABLE} -C ${IOTIVITY_SRC_DIR} add -u deps/mbedtls)
	execute_process(COMMAND ${GIT_EXECUTABLE} -C ${IOTIVITY_SRC_DIR} submodule update --init)
	execute_process(COMMAND ${GIT_EXECUTABLE} -C ${IOTIVITY_SRC_DIR} reset HEAD deps/mbedtls)
else()
	message(STATUS "Using mbedTLS v3.6.2")
	execute_process(COMMAND ${GIT_EXECUTABLE} -C ${MBEDTLS_SRC_DIR} checkout v3.6.2)
	execute_process(COMMAND ${GIT_EXECUTABLE} -C ${MBEDTLS_SRC_DIR} submodule update --init)
	execute_process(COMMAND ${GIT_EXECUTABLE} -C ${IOTIVITY_SRC_DIR} add -u deps/mbedtls)
	execute_process(COMMAND ${GIT_EXECUTABLE} -C ${IOTIVITY_SRC_DIR} submodule update --init)
	execute_process(COMMAND ${GIT_EXECUTABLE} -C ${IOTIVITY_SRC_DIR} reset HEAD deps/mbedtls)
endif()

message("submodules initialised")

if(BUILD_MBEDTLS_FORCE_3_5_0)
	execute_process(COMMAND ${GIT_EXECUTABLE} -C ${MBEDTLS_SRC_DIR} branch -D feature/iotivity-lite/v3.5.0 ERROR_QUIET)
	execute_process(COMMAND ${GIT_EXECUTABLE} -C ${MBEDTLS_SRC_DIR} checkout -b feature/iotivity-lite/v3.5.0)
	file(GLOB PATCHES_COMMON "${IOTIVITY_PATCH_DIR}/mbedtls/3.5/*.patch")
	file(GLOB PATCHES_CMAKE "${IOTIVITY_PATCH_DIR}/mbedtls/3.5/cmake/*.patch")
else()
	execute_process(COMMAND ${GIT_EXECUTABLE} -C ${MBEDTLS_SRC_DIR} branch -D feature/iotivity-lite/v3.6.2 ERROR_QUIET)
	execute_process(COMMAND ${GIT_EXECUTABLE} -C ${MBEDTLS_SRC_DIR} checkout -b feature/iotivity-lite/v3.6.2)
	file(GLOB PATCHES_COMMON "${IOTIVITY_PATCH_DIR}/mbedtls/3.6/*.patch")
	file(GLOB PATCHES_CMAKE "${IOTIVITY_PATCH_DIR}/mbedtls/3.6/cmake/*.patch")
endif()

foreach(PATCH IN LISTS PATCHES_COMMON PATCHES_CMAKE)
	message("Running patch ${PATCH}")
	execute_process(
		COMMAND ${GIT_EXECUTABLE} apply ${PATCH}
		WORKING_DIRECTORY ${MBEDTLS_SRC_DIR}
	)
endforeach()

execute_process(COMMAND ${GIT_EXECUTABLE} -C ${MBEDTLS_SRC_DIR} add -u)
execute_process(COMMAND ${GIT_EXECUTABLE} -C ${MBEDTLS_SRC_DIR} add include/mbedtls/mbedtls_oc_platform-standalone.h.in include/mbedtls/mbedtls_oc_platform.h.in)

set(MBEDTLS_INCLUDE_DIR "${IOTIVITY_SRC_DIR}/deps/mbedtls/include/mbedtls")

if(ENABLE_TESTING OR ENABLE_PROGRAMS)
	# configure variables for mbedtls_oc_platform-standalone.in
	if(OC_LOG_MAXIMUM_LEVEL)
		set(OC_LOG_MAXIMUM_LEVEL_MACRO "#define OC_LOG_MAXIMUM_LEVEL (${OC_LOG_MAXIMUM_LEVEL})")
	endif()

	if(OC_DYNAMIC_ALLOCATION_ENABLED)
		set(OC_DYNAMIC_ALLOCATION_MACRO "#define OC_DYNAMIC_ALLOCATION")
	endif()

	if(OC_PKI_ENABLED)
		set(OC_PKI_MACRO "#define OC_PKI")
	endif()

	if(OC_OSCORE_ENABLED)
		set(OC_OSCORE_MACRO "#define OC_OSCORE")
	endif()

	# support for compilation of standalone binaries
	configure_file(${MBEDTLS_INCLUDE_DIR}/mbedtls_oc_platform-standalone.h.in ${MBEDTLS_INCLUDE_DIR}/mbedtls_oc_platform.h @ONLY)
else()
	configure_file(${MBEDTLS_INCLUDE_DIR}/mbedtls_oc_platform.h.in ${MBEDTLS_INCLUDE_DIR}/mbedtls_oc_platform.h @ONLY)
endif()
