# This CMakeLists can only build the port for Linux & Windows
if(UNIX OR WIN32)
    project(iotivity-lite-port)

    add_library(iotivity-port INTERFACE)

    target_include_directories(iotivity-port INTERFACE 
	${PORT_DIR}
	${PROJECT_SOURCE_DIR}/port
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
endif()