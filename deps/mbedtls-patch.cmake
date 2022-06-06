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

execute_process(COMMAND ${GIT_EXECUTABLE} -C ${IOTIVITY_SRC_DIR} submodule update --init)

message("submodules initialised")

file(GLOB PATCHES_COMMON "${IOTIVITY_PATCH_DIR}/*.patch")
file(GLOB PATCHES_CMAKE "${IOTIVITY_PATCH_DIR}/cmake/*.patch")

foreach(PATCH IN LISTS PATCHES_COMMON PATCHES_CMAKE)
	message("Running patch ${PATCH}")
	execute_process(
		COMMAND ${GIT_EXECUTABLE} apply ${PATCH}
		WORKING_DIRECTORY ${MBEDTLS_SRC_DIR}
	)
endforeach()

# configure variables for mbedtls_oc_platform.in
if(OC_DEBUG_ENABLED)
	set(OC_DEBUG_MACRO "#define OC_DEBUG")
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

set(MBEDTLS_INCLUDE_DIR "${IOTIVITY_SRC_DIR}/deps/mbedtls/include/mbedtls")
configure_file(${MBEDTLS_INCLUDE_DIR}/mbedtls_oc_platform.h.in ${MBEDTLS_INCLUDE_DIR}/mbedtls_oc_platform.h @ONLY)
