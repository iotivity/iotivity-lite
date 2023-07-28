#----------------------------------------------------------------
# Generated CMake target import file.
#----------------------------------------------------------------

# Commands may need to know the format version.
set(CMAKE_IMPORT_FILE_VERSION 1)

# Import target "iotivity-lite::client-static" for configuration ""
set_property(TARGET iotivity-lite::client-static APPEND PROPERTY IMPORTED_CONFIGURATIONS NOCONFIG)
set_target_properties(iotivity-lite::client-static PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_NOCONFIG "C"
  IMPORTED_LOCATION_NOCONFIG "${_IMPORT_PREFIX}/lib/libiotivity-lite-client-static.a"
  )

list(APPEND _IMPORT_CHECK_TARGETS iotivity-lite::client-static )
list(APPEND _IMPORT_CHECK_FILES_FOR_iotivity-lite::client-static "${_IMPORT_PREFIX}/lib/libiotivity-lite-client-static.a" )

# Import target "iotivity-lite::client-shared" for configuration ""
set_property(TARGET iotivity-lite::client-shared APPEND PROPERTY IMPORTED_CONFIGURATIONS NOCONFIG)
set_target_properties(iotivity-lite::client-shared PROPERTIES
  IMPORTED_LOCATION_NOCONFIG "${_IMPORT_PREFIX}/lib/libiotivity-lite-client.so.2.2.5"
  IMPORTED_SONAME_NOCONFIG "libiotivity-lite-client.so.2"
  )

list(APPEND _IMPORT_CHECK_TARGETS iotivity-lite::client-shared )
list(APPEND _IMPORT_CHECK_FILES_FOR_iotivity-lite::client-shared "${_IMPORT_PREFIX}/lib/libiotivity-lite-client.so.2.2.5" )

# Import target "iotivity-lite::server-static" for configuration ""
set_property(TARGET iotivity-lite::server-static APPEND PROPERTY IMPORTED_CONFIGURATIONS NOCONFIG)
set_target_properties(iotivity-lite::server-static PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_NOCONFIG "C"
  IMPORTED_LOCATION_NOCONFIG "${_IMPORT_PREFIX}/lib/libiotivity-lite-server-static.a"
  )

list(APPEND _IMPORT_CHECK_TARGETS iotivity-lite::server-static )
list(APPEND _IMPORT_CHECK_FILES_FOR_iotivity-lite::server-static "${_IMPORT_PREFIX}/lib/libiotivity-lite-server-static.a" )

# Import target "iotivity-lite::server-shared" for configuration ""
set_property(TARGET iotivity-lite::server-shared APPEND PROPERTY IMPORTED_CONFIGURATIONS NOCONFIG)
set_target_properties(iotivity-lite::server-shared PROPERTIES
  IMPORTED_LOCATION_NOCONFIG "${_IMPORT_PREFIX}/lib/libiotivity-lite-server.so.2.2.5"
  IMPORTED_SONAME_NOCONFIG "libiotivity-lite-server.so.2"
  )

list(APPEND _IMPORT_CHECK_TARGETS iotivity-lite::server-shared )
list(APPEND _IMPORT_CHECK_FILES_FOR_iotivity-lite::server-shared "${_IMPORT_PREFIX}/lib/libiotivity-lite-server.so.2.2.5" )

# Import target "iotivity-lite::client-server-static" for configuration ""
set_property(TARGET iotivity-lite::client-server-static APPEND PROPERTY IMPORTED_CONFIGURATIONS NOCONFIG)
set_target_properties(iotivity-lite::client-server-static PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_NOCONFIG "C"
  IMPORTED_LOCATION_NOCONFIG "${_IMPORT_PREFIX}/lib/libiotivity-lite-client-server-static.a"
  )

list(APPEND _IMPORT_CHECK_TARGETS iotivity-lite::client-server-static )
list(APPEND _IMPORT_CHECK_FILES_FOR_iotivity-lite::client-server-static "${_IMPORT_PREFIX}/lib/libiotivity-lite-client-server-static.a" )

# Import target "iotivity-lite::client-server-shared" for configuration ""
set_property(TARGET iotivity-lite::client-server-shared APPEND PROPERTY IMPORTED_CONFIGURATIONS NOCONFIG)
set_target_properties(iotivity-lite::client-server-shared PROPERTIES
  IMPORTED_LOCATION_NOCONFIG "${_IMPORT_PREFIX}/lib/libiotivity-lite-client-server.so.2.2.5"
  IMPORTED_SONAME_NOCONFIG "libiotivity-lite-client-server.so.2"
  )

list(APPEND _IMPORT_CHECK_TARGETS iotivity-lite::client-server-shared )
list(APPEND _IMPORT_CHECK_FILES_FOR_iotivity-lite::client-server-shared "${_IMPORT_PREFIX}/lib/libiotivity-lite-client-server.so.2.2.5" )

# Commands beyond this point should not need to know the version.
set(CMAKE_IMPORT_FILE_VERSION)
