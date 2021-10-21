project(iotivity-lite-apps)

if(UNIX)
    add_executable(simpleserver
        ${PROJECT_SOURCE_DIR}/simpleserver.c
        ${iotivity-lite_SOURCE_DIR}/api/oc_introspection.c
    )
    target_link_libraries(simpleserver
        iotivity-server-client
    )
    file(MAKE_DIRECTORY ${PROJECT_BINARY_DIR}/simpleserver_creds)

    add_executable(simpleserver_pki
        ${PROJECT_SOURCE_DIR}/simpleserver_pki.c
        ${iotivity-lite_SOURCE_DIR}/api/oc_introspection.c
    )
    target_link_libraries(simpleserver_pki
        iotivity-server-client
    )
    file(MAKE_DIRECTORY ${PROJECT_BINARY_DIR}/simpleserver_pki_creds)

    add_executable(simpleclient
        ${PROJECT_SOURCE_DIR}/simpleclient.c
        ${iotivity-lite_SOURCE_DIR}/api/oc_introspection.c
    )
    target_link_libraries(simpleclient
        iotivity-client
    )
    file(MAKE_DIRECTORY ${PROJECT_BINARY_DIR}/simpleclient_creds)

    if(EXISTS ${PROJECT_SOURCE_DIR}/device_builder_server.c)
        add_executable(device_builder_server
            ${PROJECT_SOURCE_DIR}/device_builder_server.c
            ${iotivity-lite_SOURCE_DIR}/api/oc_introspection.c
        )
        target_link_libraries(device_builder_server
            iotivity-server-client
        )
        file(MAKE_DIRECTORY ${PROJECT_BINARY_DIR}/device_builder_server_creds)
    endif()

    if(OC_TCP_ENABLED AND OC_CLOUD_ENABLED)
        add_executable(cloud_proxy
            ${PROJECT_SOURCE_DIR}/cloud_proxy.c
            ${iotivity-lite_SOURCE_DIR}/api/oc_introspection.c
        )
        target_link_libraries(cloud_proxy
            iotivity-server-client
        )
        file(MAKE_DIRECTORY ${PROJECT_BINARY_DIR}/simpleserver_creds)
    endif()
elseif(WIN32)
    add_executable(simpleserver
        ${PROJECT_SOURCE_DIR}/simpleserver_windows.c
        ${iotivity-lite_SOURCE_DIR}/api/oc_introspection.c
    )
    target_link_libraries(simpleserver
        iotivity-server-client
    )
    file(MAKE_DIRECTORY ${PROJECT_BINARY_DIR}/simpleserver_creds)

    add_executable(simpleclient
        ${PROJECT_SOURCE_DIR}/simpleclient_windows.c
        ${iotivity-lite_SOURCE_DIR}/api/oc_introspection.c
    )
    target_link_libraries(simpleclient
        iotivity-server-client
    )
    file(MAKE_DIRECTORY ${PROJECT_BINARY_DIR}/simpleclient_creds)
endif()

# copy credentials, used by example applications.
add_custom_target(copy-pki-certs ALL
    COMMAND ${CMAKE_COMMAND} -E copy_directory
    ${PROJECT_SOURCE_DIR}/pki_certs
    ${PROJECT_BINARY_DIR}/pki_certs
)

add_dependencies(iotivity-port copy-pki-credentials)