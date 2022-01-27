# This CMakeLists can only build the port for Linux & Windows
if(NOT (UNIX OR WIN32))
    message(ERROR "Can build only on Linux and windows")
endif()
# Detect the platform and pick the right port
if(UNIX)
    set(PORT_DIR ${PROJECT_SOURCE_DIR}/port/linux)
    file(GLOB PORT_SRC port/linux/*.c)
elseif(WIN32)
    set(PORT_DIR ${PROJECT_SOURCE_DIR}/port/windows)
    file(GLOB PORT_SRC port/windows/*.c)
endif()

add_library(iotivity-port OBJECT
    ${PORT_SRC}
)

target_compile_definitions(iotivity-port PRIVATE ${PUBLIC_COMPILER_DEFS})

target_include_directories(iotivity-port PRIVATE
    ${PROJECT_SOURCE_DIR}
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/port
    ${PORT_DIR}
)

# Install headers
install(DIRECTORY ${PROJECT_SOURCE_DIR}/port
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/iotivity-lite COMPONENT dev
    FILES_MATCHING PATTERN "*.h"
)
install(FILES ${PORT_DIR}/oc_config.h
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/iotivity-lite COMPONENT dev
)

######## Generate pkg-config and cmake files ########
foreach(lib IN LISTS PUBLIC_LINK_LIBS)
    string(APPEND extra_libs "-l${lib} ")
endforeach()
foreach(cflag IN LISTS PUBLIC_COMPILER_DEFS)
    string(APPEND extra_cflags "-D${cflag} ")
endforeach()

# Generate pkg-config files
set(prefix ${CMAKE_INSTALL_PREFIX})
set(exec_prefix "\${prefix}")
set(libdir "\${prefix}/${CMAKE_INSTALL_LIBDIR}")
set(includedir "\${prefix}/${CMAKE_INSTALL_INCLUDEDIR}")
set(version ${iotivity-lite_VERSION})

set(PKG_CONFIG_FILES
    iotivity-lite-client.pc
    iotivity-lite-server.pc
    iotivity-lite-client-server.pc)
foreach(pkg-config-file IN LISTS PKG_CONFIG_FILES)
    configure_file(
        "${PROJECT_SOURCE_DIR}/port/linux/${pkg-config-file}.in"
        ${pkg-config-file}
        @ONLY)
    install(FILES ${CMAKE_CURRENT_BINARY_DIR}/${pkg-config-file}
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig COMPONENT dev)
endforeach()
