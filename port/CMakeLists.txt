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

    target_include_directories(mbedcrypto PUBLIC
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

    message("PORT_DIR = ${PORT_DIR}")
    file(COPY ${PORT_DIR}/server_introspection.cbor
        DESTINATION ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/)
    #add_custom_command(
            #TARGET iotivity-lite POST_BUILD
            #COMMAND ${CMAKE_COMMAND} -E copy
                    #${PORT_DIR}/server_introspection.cbor
                    #${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/server_introspection.cbor)

endif()
