add_library(tinycbor-master OBJECT
    ${PROJECT_SOURCE_DIR}/deps/tinycbor/src/cborerrorstrings.c
    ${PROJECT_SOURCE_DIR}/deps/tinycbor/src/cborencoder.c
    ${PROJECT_SOURCE_DIR}/deps/tinycbor/src/cborencoder_close_container_checked.c
    ${PROJECT_SOURCE_DIR}/deps/tinycbor/src/cborparser.c
    ${PROJECT_SOURCE_DIR}/deps/tinycbor/src/cborpretty.c
)

target_include_directories(tinycbor-master PUBLIC
    ${PROJECT_SOURCE_DIR}/deps/tinycbor/src
)

target_compile_definitions(tinycbor-master PUBLIC ${PUBLIC_COMPILE_DEFINITIONS})

install(DIRECTORY ${PROJECT_SOURCE_DIR}/deps/tinycbor/src/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/iotivity-lite/deps/tinycbor/src COMPONENT dev
    FILES_MATCHING PATTERN "*.h"
)
