project(iotivity-lite-apps)


# platform-independent applications
if(OC_CLOUD_ENABLED)
    add_executable(cloud_server
        ${PROJECT_SOURCE_DIR}/cloud_server.c
    )
    target_compile_options(cloud_server PRIVATE ${PRIVATE_COMPILE_OPTIONS})
    target_link_libraries(cloud_server client-server-static)
    file(MAKE_DIRECTORY ${PROJECT_BINARY_DIR}/cloud_server_creds)
endif()

# platform-specific applications
if(UNIX)
    add_executable(simpleserver
        ${PROJECT_SOURCE_DIR}/simpleserver.c
    )
    target_compile_options(simpleserver PRIVATE ${PRIVATE_COMPILE_OPTIONS})
    target_link_libraries(simpleserver server-static)
    file(MAKE_DIRECTORY ${PROJECT_BINARY_DIR}/simpleserver_creds)

    if(OC_SECURITY_ENABLED AND OC_PKI_ENABLED)
        add_executable(simpleserver_pki
            ${PROJECT_SOURCE_DIR}/simpleserver_pki.c
        )
        target_compile_options(simpleserver_pki PRIVATE ${PRIVATE_COMPILE_OPTIONS})
        target_link_libraries(simpleserver_pki server-static)
        file(MAKE_DIRECTORY ${PROJECT_BINARY_DIR}/simpleserver_pki_creds)
    endif()

    add_executable(simpleclient
        ${PROJECT_SOURCE_DIR}/simpleclient.c
    )
    target_compile_options(simpleclient PRIVATE ${PRIVATE_COMPILE_OPTIONS})
    target_link_libraries(simpleclient client-static)
    file(MAKE_DIRECTORY ${PROJECT_BINARY_DIR}/simpleclient_creds)

    add_executable(server
        ${PROJECT_SOURCE_DIR}/server_linux.c
    )
    target_compile_options(server PRIVATE ${PRIVATE_COMPILE_OPTIONS})
    target_link_libraries(server server-static)
    file(MAKE_DIRECTORY ${PROJECT_BINARY_DIR}/server_creds)

    add_executable(client
        ${PROJECT_SOURCE_DIR}/client_linux.c
    )
    target_compile_options(client PRIVATE ${PRIVATE_COMPILE_OPTIONS})
    target_link_libraries(client client-static)
    file(MAKE_DIRECTORY ${PROJECT_BINARY_DIR}/client_creds)

    add_executable(server_block_linux
        ${PROJECT_SOURCE_DIR}/server_block_linux.c
    )
    target_compile_options(server_block_linux PRIVATE ${PRIVATE_COMPILE_OPTIONS})
    target_link_libraries(server_block_linux server-static)
    file(MAKE_DIRECTORY ${PROJECT_BINARY_DIR}/server_block_linux_creds)

    add_executable(client_block_linux
        ${PROJECT_SOURCE_DIR}/client_block_linux.c
    )
    target_compile_options(client_block_linux PRIVATE ${PRIVATE_COMPILE_OPTIONS})
    target_link_libraries(client_block_linux client-static)
    file(MAKE_DIRECTORY ${PROJECT_BINARY_DIR}/client_block_linux_creds)

    add_executable(server_multithread_linux
        ${PROJECT_SOURCE_DIR}/server_multithread_linux.c
    )
    target_compile_options(server_multithread_linux PRIVATE ${PRIVATE_COMPILE_OPTIONS})
    target_link_libraries(server_multithread_linux server-static)
    file(MAKE_DIRECTORY ${PROJECT_BINARY_DIR}/server_multithread_linux_creds)

    add_executable(client_multithread_linux
        ${PROJECT_SOURCE_DIR}/client_multithread_linux.c
    )
    target_compile_options(client_multithread_linux PRIVATE ${PRIVATE_COMPILE_OPTIONS})
    target_link_libraries(client_multithread_linux client-static)
    file(MAKE_DIRECTORY ${PROJECT_BINARY_DIR}/client_multithread_linux_creds)

    add_executable(multi_device_server
        ${PROJECT_SOURCE_DIR}/multi_device_server_linux.c
    )
    target_compile_options(multi_device_server PRIVATE ${PRIVATE_COMPILE_OPTIONS})
    target_link_libraries(multi_device_server server-static)
    file(MAKE_DIRECTORY ${PROJECT_BINARY_DIR}/multi_device_server_creds)

    add_executable(multi_device_client
        ${PROJECT_SOURCE_DIR}/multi_device_client_linux.c
    )
    target_compile_options(multi_device_client PRIVATE ${PRIVATE_COMPILE_OPTIONS})
    target_link_libraries(multi_device_client client-static)
    file(MAKE_DIRECTORY ${PROJECT_BINARY_DIR}/multi_device_client_creds)

    add_executable(secure_mcast_server1
        ${PROJECT_SOURCE_DIR}/secure_mcast_server1.c
    )
    target_compile_options(secure_mcast_server1 PRIVATE ${PRIVATE_COMPILE_OPTIONS})
    target_link_libraries(secure_mcast_server1 server-static)
    file(MAKE_DIRECTORY ${PROJECT_BINARY_DIR}/secure_mcast_server1_creds)

    add_executable(secure_mcast_server2
        ${PROJECT_SOURCE_DIR}/secure_mcast_server2.c
    )
    target_compile_options(secure_mcast_server2 PRIVATE ${PRIVATE_COMPILE_OPTIONS})
    target_link_libraries(secure_mcast_server2 server-static)
    file(MAKE_DIRECTORY ${PROJECT_BINARY_DIR}/secure_mcast_server2_creds)

    add_executable(secure_mcast_client
        ${PROJECT_SOURCE_DIR}/secure_mcast_client.c
    )
    target_compile_options(secure_mcast_client PRIVATE ${PRIVATE_COMPILE_OPTIONS})
    target_link_libraries(secure_mcast_client client-static)
    file(MAKE_DIRECTORY ${PROJECT_BINARY_DIR}/secure_mcast_client_creds)

    add_executable(smart_home_server_linux
        ${PROJECT_SOURCE_DIR}/smart_home_server_linux.c
    )
    target_compile_options(smart_home_server_linux PRIVATE ${PRIVATE_COMPILE_OPTIONS})
    target_link_libraries(smart_home_server_linux server-static)
    file(MAKE_DIRECTORY ${PROJECT_BINARY_DIR}/smart_home_server_linux_creds)

    add_executable(smart_home_server_with_mock_swupdate
        ${PROJECT_SOURCE_DIR}/smart_home_server_with_mock_swupdate.cpp
    )
    target_compile_options(smart_home_server_with_mock_swupdate PRIVATE ${PRIVATE_COMPILE_OPTIONS})
    target_link_libraries(smart_home_server_with_mock_swupdate server-static)
    file(MAKE_DIRECTORY ${PROJECT_BINARY_DIR}/smart_home_server_with_mock_swupdate_creds)

    add_executable(server_rules
        ${PROJECT_SOURCE_DIR}/server_rules.c
    )
    target_compile_options(server_rules PRIVATE ${PRIVATE_COMPILE_OPTIONS})
    target_link_libraries(server_rules server-static)
    file(MAKE_DIRECTORY ${PROJECT_BINARY_DIR}/server_rules_creds)

    add_executable(server_certification_tests
        ${PROJECT_SOURCE_DIR}/server_certification_tests.c
    )
    target_compile_options(server_certification_tests PRIVATE ${PRIVATE_COMPILE_OPTIONS})
    target_link_libraries(server_certification_tests client-server-static)
    file(MAKE_DIRECTORY ${PROJECT_BINARY_DIR}/server_certification_tests_creds)

    add_executable(client_certification_tests
        ${PROJECT_SOURCE_DIR}/client_certification_tests.c
    )
    target_compile_options(client_certification_tests PRIVATE ${PRIVATE_COMPILE_OPTIONS})
    target_link_libraries(client_certification_tests client-server-static)
    file(MAKE_DIRECTORY ${PROJECT_BINARY_DIR}/client_certification_tests_creds)

    if(OC_CLOUD_ENABLED)
        add_executable(cloud_client
            ${PROJECT_SOURCE_DIR}/cloud_client.c
        )
        target_compile_options(cloud_client PRIVATE ${PRIVATE_COMPILE_OPTIONS})
        target_link_libraries(cloud_client client-server-static)
        file(MAKE_DIRECTORY ${PROJECT_BINARY_DIR}/cloud_client_creds)

        add_executable(cloud_proxy
            ${PROJECT_SOURCE_DIR}/cloud_proxy.c
        )
        target_compile_options(cloud_proxy PRIVATE ${PRIVATE_COMPILE_OPTIONS})
        target_link_libraries(cloud_proxy client-server-static)
        file(MAKE_DIRECTORY ${PROJECT_BINARY_DIR}/cloud_proxy_creds)

        add_executable(cloud_tests
            ${PROJECT_SOURCE_DIR}/cloud_certification_tests.c
        )
        target_compile_options(cloud_tests PRIVATE ${PRIVATE_COMPILE_OPTIONS})
        target_link_libraries(cloud_tests client-server-static)
        file(MAKE_DIRECTORY ${PROJECT_BINARY_DIR}/cloud_tests_creds)
    endif()

    if(EXISTS ${PROJECT_SOURCE_DIR}/device_builder_server.c)
        add_executable(device_builder_server
            ${PROJECT_SOURCE_DIR}/device_builder_server.c
        )
        target_compile_options(device_builder_server PRIVATE ${PRIVATE_COMPILE_OPTIONS})
        target_link_libraries(device_builder_server client-server-static)
        file(MAKE_DIRECTORY ${PROJECT_BINARY_DIR}/device_builder_server_creds)
    endif()

    if(OC_PUSH_ENABLED AND OC_COLLECTIONS_IF_CREATE_ENABLED AND OC_DYNAMIC_ALLOCATION_ENABLED)
        add_executable(push_originserver_multithread_linux
            ${PROJECT_SOURCE_DIR}/push_originserver_multithread_linux.c
        )
        target_compile_options(push_originserver_multithread_linux PRIVATE ${PRIVATE_COMPILE_OPTIONS})
        target_link_libraries(push_originserver_multithread_linux client-server-static)
        file(MAKE_DIRECTORY ${PROJECT_BINARY_DIR}/push_originserver_multithread_linux_creds)
        
        add_executable(push_targetserver_multithread_linux
            ${PROJECT_SOURCE_DIR}/push_targetserver_multithread_linux.c
        )
        target_compile_options(push_targetserver_multithread_linux PRIVATE ${PRIVATE_COMPILE_OPTIONS})
        target_link_libraries(push_targetserver_multithread_linux client-server-static)
        file(MAKE_DIRECTORY ${PROJECT_BINARY_DIR}/push_targetserver_multithread_linux_creds)
        
        add_executable(push_configurator_multithread_linux
            ${PROJECT_SOURCE_DIR}/push_configurator_multithread_linux.c
        )
        target_compile_options(push_configurator_multithread_linux PRIVATE ${PRIVATE_COMPILE_OPTIONS})
        target_link_libraries(push_configurator_multithread_linux client-server-static)
        file(MAKE_DIRECTORY ${PROJECT_BINARY_DIR}/push_configurator_multithread_linux_creds)
    endif()
elseif(WIN32)
    add_executable(simpleserver
        ${PROJECT_SOURCE_DIR}/simpleserver_windows.c
    )
    target_compile_options(simpleserver PRIVATE ${PRIVATE_COMPILE_OPTIONS})
    target_link_libraries(simpleserver client-server-static)
    file(MAKE_DIRECTORY ${PROJECT_BINARY_DIR}/simpleserver_creds)

    add_executable(simpleclient
        ${PROJECT_SOURCE_DIR}/simpleclient_windows.c
    )
    target_compile_options(simpleclient PRIVATE ${PRIVATE_COMPILE_OPTIONS})
    target_link_libraries(simpleclient client-server-static)
    file(MAKE_DIRECTORY ${PROJECT_BINARY_DIR}/simpleclient_creds)
endif()

# copy credentials, used by example applications.
add_custom_target(copy-pki-certs ALL
    COMMAND ${CMAKE_COMMAND} -E copy_directory
    ${PROJECT_SOURCE_DIR}/pki_certs
    ${PROJECT_BINARY_DIR}/pki_certs
)
add_dependencies(client-server-static copy-pki-certs)

if(OC_IDD_API_ENABLED)
    # copy introspection files, used by certification applications.
    add_custom_target(copy-idd-files ALL
        COMMAND ${CMAKE_COMMAND} -E copy
        ${PROJECT_SOURCE_DIR}/server_certification_tests_IDD.cbor
        ${PROJECT_SOURCE_DIR}/client_certification_tests_IDD.cbor
        ${PROJECT_SOURCE_DIR}/server_rules_IDD.cbor
        ${PROJECT_SOURCE_DIR}/cloud_proxy_IDD.cbor
        ${PROJECT_SOURCE_DIR}/smart_home_server_linux_IDD.cbor
        ${PROJECT_BINARY_DIR}
    )
    add_dependencies(client-server-static copy-idd-files)
endif()
