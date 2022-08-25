
set(iotivity_src "${CMAKE_CURRENT_SOURCE_DIR}/../../../..")
set(esp_src "${CMAKE_CURRENT_SOURCE_DIR}/../..")

idf_component_register(
	SRCS 
		"${esp_src}/hawkbit_util.c"
		"hawkbit_util_test.c"
		"test_main.c"
	INCLUDE_DIRS "."
	REQUIRES unity
	WHOLE_ARCHIVE
)

set_source_files_properties(${sources}
	PROPERTIES COMPILE_FLAGS
	"-DOC_SERVER -DOC_CLIENT"
)
