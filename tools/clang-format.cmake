cmake_minimum_required (VERSION 3.11)

# Create list of all source files
file(GLOB_RECURSE iotivity_allsource *.c *.cpp *.h *.hpp)
# Remove third party code
list(FILTER iotivity_allsource EXCLUDE REGEX "deps/")

# Find clang-format
find_program(
	CLANG_FORMAT_EXE
	NAMES "clang-format-6.0"
	      "clang-format"
	DOC "Path to clang-format executable"
	)
if(NOT CLANG_FORMAT_EXE)
	message(FATAL_ERROR "clang-format not found.")
else()
	message(STATUS "clang-format found: ${CLANG_FORMAT_EXE}")
endif()

execute_process(
	COMMAND ${CLANG_FORMAT_EXE} -version
	OUTPUT_VARIABLE CLANG_VERSION
	)

# version check
if(NOT ${CLANG_VERSION} MATCHES "version 6\.0")
	message(FATAL_ERROR "clang-format must be version 6.0")
endif()

# Run clang format
list(LENGTH iotivity_allsource LIST_LEN)
math(EXPR LIST_LEN "${LIST_LEN} - 1")
foreach(INDEX RANGE 0 ${LIST_LEN} 8)
	list(SUBLIST iotivity_allsource ${INDEX} 8 TMP_PATH)
	execute_process(COMMAND ${CLANG_FORMAT_EXE} -i ${TMP_PATH})
endforeach()
