# This CMakeLists can only build the port for Linux & Windows
if(UNIX OR WIN32)
    project(iotivity-lite-port)

    # Detect the platform and pick the right port
    if(UNIX)
        set(PORT_DIR ${PROJECT_SOURCE_DIR}/linux)
    elseif(WIN32)
        set(PORT_DIR ${PROJECT_SOURCE_DIR}/windows)
    endif()


    add_library(iotivity-port INTERFACE)

    target_include_directories(iotivity-port INTERFACE 
        ${PORT_DIR}
        ${PROJECT_SOURCE_DIR}
    )

    target_sources(iotivity-port INTERFACE
        ${PORT_DIR}/abort.c
        ${PORT_DIR}/clock.c
        ${PORT_DIR}/ipadapter.c
        ${PORT_DIR}/random.c
        ${PORT_DIR}/storage.c
        ${PORT_DIR}/tcpadapter.c
    )
    
    if(WIN32)
        target_sources(iotivity-port INTERFACE
            ${PORT_DIR}/mutex.c
            ${PORT_DIR}/network_addresses.c
        )
        target_compile_definitions(iotivity-port INTERFACE OC_IPV4)
    endif()
    
    if(UNIX)
        target_link_libraries(iotivity-port INTERFACE pthread m)
    elseif(WIN32)
        target_link_libraries(iotivity-port INTERFACE bcrypt iphlpapi)
    endif()
    
    # Install headers
    install(DIRECTORY ${PROJECT_SOURCE_DIR}
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/iotivity-lite COMPONENT dev
        FILES_MATCHING PATTERN "*.h"
    )
    if(UNIX)
        install(FILES linux/oc_config.h
            DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/iotivity-lite COMPONENT dev
        )
    elseif(WIN32)
        install(FILES windows/oc_config.h
            DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/iotivity-lite COMPONENT dev
        )
    endif()
    
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
            "linux/${pkg-config-file}.in"
            ${pkg-config-file}
            @ONLY)
        install(FILES ${CMAKE_CURRENT_BINARY_DIR}/${pkg-config-file}
            DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)
    endforeach()
endif()
