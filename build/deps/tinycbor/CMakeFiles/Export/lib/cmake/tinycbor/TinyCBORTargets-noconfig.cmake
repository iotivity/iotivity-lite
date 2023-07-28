#----------------------------------------------------------------
# Generated CMake target import file.
#----------------------------------------------------------------

# Commands may need to know the format version.
set(CMAKE_IMPORT_FILE_VERSION 1)

# Import target "TinyCBOR::tinycbor" for configuration ""
set_property(TARGET TinyCBOR::tinycbor APPEND PROPERTY IMPORTED_CONFIGURATIONS NOCONFIG)
set_target_properties(TinyCBOR::tinycbor PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_NOCONFIG "C"
  IMPORTED_LOCATION_NOCONFIG "${_IMPORT_PREFIX}/lib/libtinycbor.a"
  )

list(APPEND _IMPORT_CHECK_TARGETS TinyCBOR::tinycbor )
list(APPEND _IMPORT_CHECK_FILES_FOR_TinyCBOR::tinycbor "${_IMPORT_PREFIX}/lib/libtinycbor.a" )

# Commands beyond this point should not need to know the version.
set(CMAKE_IMPORT_FILE_VERSION)
