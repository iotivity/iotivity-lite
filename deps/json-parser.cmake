add_library(json-parser OBJECT
    ${PROJECT_SOURCE_DIR}/deps/json-parser/json.c
)

target_include_directories(json-parser PUBLIC
    ${PROJECT_SOURCE_DIR}/deps/json-parser
)

target_compile_definitions(json-parser PUBLIC ${PUBLIC_COMPILE_DEFINITIONS})

install(DIRECTORY ${PROJECT_SOURCE_DIR}/deps/json-parser/src/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/iotivity-lite/deps/json-parser COMPONENT dev
    FILES_MATCHING PATTERN "*.h"
)
