project(iotivity-deps)

add_library(tinycbor-master
    ${PROJECT_SOURCE_DIR}/tinycbor/src/cborerrorstrings.c
    ${PROJECT_SOURCE_DIR}/tinycbor/src/cborencoder.c
    ${PROJECT_SOURCE_DIR}/tinycbor/src/cborencoder_close_container_checked.c
    ${PROJECT_SOURCE_DIR}/tinycbor/src/cborparser.c
    ${PROJECT_SOURCE_DIR}/tinycbor/src/cborpretty.c
)

target_include_directories(tinycbor-master PUBLIC
    ${PROJECT_SOURCE_DIR}/tinycbor/src
)

install(DIRECTORY tinycbor/src/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/iotivity-lite/deps/tinycbor/src COMPONENT dev
    FILES_MATCHING PATTERN "*.h"
)
