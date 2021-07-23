cmake_minimum_required(VERSION 3.5)

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(example)

idf_build_get_property(config_dir CONFIG_DIR)
set(sdkconfig_header ${config_dir}/sdkconfig.h)
set(project_elf ${CMAKE_PROJECT_NAME}.elf)
