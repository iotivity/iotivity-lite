# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(hello_world)

set(CONFIG_FILE_SYSTEM ON CACHE BOOL "Use file system")
#target_include_directories(app PRIVATE $ENV{ZEPHYR_BASE}/include/posix)
add_subdirectory(${PROJECT_SOURCE_DIR}/../.. iotivity-lite)
#target_sources(app PRIVATE ../../apps/server_zephyr.c)
target_sources(app PRIVATE src/main.c)
target_link_libraries(app PRIVATE client-server-static)
