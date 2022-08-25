cmake_minimum_required(VERSION 3.5)

# project version obtainable in runtime by esp_app_get_description
set(PROJECT_VER "1.0")

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/../..
    ${CMAKE_CURRENT_SOURCE_DIR}/../../include
    ${CMAKE_CURRENT_SOURCE_DIR}/adapter/include
)
project(example)

idf_build_get_property(config_dir CONFIG_DIR)
